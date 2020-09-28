import logging
import hashlib
import os
import aiofiles

from modules.Infrastructure import client
from modules.Infrastructure import errno
from utils.General import parse_config
from utils.extra import netparse
from utils.extra import create_translation

server_config = parse_config.parse()["Server"]
server_data = os.path.join(
    server_config["init_path"], server_config["server_data"]
        
)
logger = logging.getLogger(__name__)
exp_func = lambda level: logger.isEnabledFor(level)

_ = create_translation.create(
    "admin",
    os.getenv("UTESLA_LOCALES_SERVICES") or \
    "services-locales"
    
)

class Handler:
    @staticmethod
    def __set_correct_path(path, /):
        if (path != "/") and (path[:1] == "/"):
            path = path[1:]

        return path

    def SET_CONTROLLER(self, controller, /):
        self.controller = controller
        controller.template.set_function_expression(exp_func)
        self.get_template = controller.template.get_template
        self.procs = controller.procs

    async def access(self):
        if not (self.controller.request.token):
            logger.error(_("%s: El token no ha sido definido"), self.get_template(logging.ERROR))

            await self.controller.write_status(errno.ENOTOK)
            return

        token = self.controller.pool.callback.token2hash(self.controller.request.token)

        if (await self.controller.pool.return_first_result("token_exists", token)):
            if (await self.controller.pool.return_first_result("is_expired", token)):
                logger.warning(_("%s: ¡El token ha expirado!"), self.get_template(logging.WARNING))

                logger.debug(
                    _("%s: Eliminando token del usuario por acabar en el límite de la expiración"),
                    self.get_template(logging.DEBUG)

                )

                await self.pool.return_first_result("delete_token", token)

                if (await self.pool.return_first_result("token_exists", token)):
                    logger.warning(
                        _("%s: Hubo un problema borrando el token expirado del usuario"),
                        self.get_template(logging.WARNING)
                        
                    )

                await self.controller.write_status(errno.ETOKEXPIRED)

                return False

            else:
                return True

        else:
            logger.warning(
                _("%s: ¡El token del usuario no existe!"),
                self.get_template(logging.WARNING)
                
            )

            await self.controller.write_status(errno.ENOTOK, _("El token no existe"))

            return False

    async def __parse_node(self, node):
        networkid = await self.controller.pool.return_first_result("extract_networkid", node)
        
        if (networkid is None):
            logger.warning(
                _("%s: ¡El nodo '%s' no forma parte de la red!"),
                self.get_template(logging.WARNING), node
                
            )

            await self.controller.write_status(errno.ECLIENT, _("El nodo proporcionado no forma parte de la red"))
            return

        else:
            (networkid,) = networkid

        path = self.__set_correct_path(self.controller.request.path)

        serviceid = await self.controller.pool.return_first_result("extract_serviceid", path)

        if (serviceid is None):
            logger.warning(
                _("%s: El servicio no existe"),
                self.get_template(logging.WARNING)
                
            )
            return

        else:
            (serviceid,) = serviceid

        network_in_service = await self.controller.pool.return_first_result("network_in_service", networkid, serviceid)

        if (network_in_service):
            yield (networkid, node)

        else:
            logger.warning(
                _("%s: El servicio no es parte del nodo '%s'"),
                self.get_template(logging.WARNING), node
                
            )

    async def __resend(self, UControl):
        logger.warning(
            _("%s: Reenviando datos..."),
            self.get_template(logging.WARNING)
            
        )

        recv = await UControl.read(is_packed=self.controller.request.is_packed)

        await self.controller.write(recv, headers=UControl.request.headers)

    async def remote(self):
        # Usado para verificar si se encontró el servicio en algún nodo registrado
        init = False
        force = self.controller.request.force
        node = self.controller.request.node

        if (force):
            if (node == ()):
                logger.warning(
                    _("%s: No se definió el nodo a conectar"),
                    self.get_template(logging.WARNING)
                    
                )

                await self.controller.write_status(errno.ECLIENT, _("No definió el nodo a conectar"))
                return

            elif (len(node) != 2):
                logger.warning(
                    _("%s: La información proporcionada sobre el nodo no es correcta"),
                    self.get_template(logging.WARNING)
                    
                )

                await self.controller.write_status(errno.ECLIENT, _("La información proporcionada sobre el nodo no es correcta"))
                return

            else:
                (host, port) = node

                if not (isinstance(host, str)):
                    logger.warning(
                        _("%s: La dirección o el nombre del host no tiene un tipo correcto de dato"),
                        self.get_template(logging.WARNING)
                        
                    )

                    await self.controller.write_status(
                        errno.ECLIENT,
                        _("La dirección o el nombre del host no tiene un tipo correcto de dato")
                        
                    )
                    return

                try:
                    port = int(port)

                except (ValueError, TypeError):
                    logger.warning(
                        _("%s: El puerto del nodo no tiene un tipo correcto de dato"),
                        self.get_template(logging.WARNING)
                        
                    )

                    await self.controller.write_status(
                        errno.ECLIENT,
                        _("El puerto del nodo no tiene un tipo correcto de dato")

                    )
                    return

            networks = self.__parse_node("%s:%d" % (host, port))

        else:
            path = self.__set_correct_path(self.controller.request.path)

            networks = self.controller.pool.execute_command("service2net", path, True)

        async for network in networks:
            (networkid, node_str) = network

            try:
                (host, port, __) = netparse.parse(node_str)

            except Exception as err:
                logger.error(
                    _("%s: La dirección '%s' no es válida: %s"),
                    self.get_template(logging.ERROR), node_str, err
                    
                )
                continue

            public_key = "%s/%s" % (
                server_data, hashlib.sha3_224(node_str.encode()).hexdigest()

            )

            if not (os.path.isfile(public_key)):
                logger.warning(
                    _("%s: La clave pública '%s' del nodo '%s' no existe o no es un archivo"),
                    self.get_template(logging.warning), public_key, node_str 

                )

                await self.controller.write_status(errno.ESERVER)
                continue

            else:
                async with aiofiles.open(public_key, "rb") as fd:
                    public_key_data = await fd.read()

            token = await self.controller.pool.return_first_result("get_network_token", networkid)

            if (token is None):
                logger.warning(
                    _("%s: No se pudo obtener el token del nodo '%s'"),
                    self.get_template(logging.WARNING), node_str
                    
                )

                await self.controller.write_status(errno.ESERVER)
                continue

            else:
                (token,) = token

            user_server = await self.controller.pool.return_first_result("get_user_network", networkid)

            if (user_server is None):
                logger.warning(
                    _("%s: No se pudo obtener el nombre de usuario del nodo '%d'"),
                    self.get_template(logging.WARNING), node_str
                        
                )
                
                await self.controller.write_status(errno.ESERVER)
                continue

            else:
                (user_server,) = user_server

            logger.warning(_("%s: Conectando con %s..."), self.get_template(logging.WARNING), node_str)

            fut = client.simple_client(
                host, port, user_server, public_key_data
                
            )

            try:
                (UControl, __, sock) = await fut

            except:
                logging.exception(_("%s: ¡Error conectando con %s!"), self.get_template(logging.WARNING), node_str)
                continue

            else:
                logger.info(_("%s: Conectado: %s"), self.get_template(logging.INFO), node_str)

            # Indicamos que la operación fue exitosa
            if not (init):
                init = True
            
            # Agregamos el socket a la lista de descriptores de archivos para cerrarlo
            self.procs.locals.ProcStream.add_stream(sock, node_str)

            UControl.headers = self.controller.request.headers
            UControl.headers["force"] = False
            # No necesariamente el servicio puede requerir un token, pero todo dependerá de lo que decida el
            # administrador de ese nodo, así que igualmente se envía.
            UControl.set_token(token)
            UControl.del_node()

            # Mandamos los primeros datos que el cliente envió
            await UControl.write(self.controller.data)
            await self.__resend(UControl)

            async for data in self.controller.body:
                UControl.headers["force"] = False
                UControl.set_token(token)
                UControl.del_node()
                await UControl.write(data)
                await self.__resend(UControl)

        if not (init):
            logger.warning(
                _("%s: No se pudo encontrar un nodo que tenga el servicio requerido"),
                self.get_template(logging.WARNING),
                
            )

            await self.controller.write_status(errno.ENOENT, _("Servicio no encontrado"))
