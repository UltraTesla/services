import logging
import argon2
import re
import os

from modules.Infrastructure import errno
from modules.Infrastructure import exceptions

from utils.extra import verify_hash
from utils.extra import generate_hash
from utils.extra import create_translation

from utils.General import parse_config

config = parse_config.parse()
crypt_limits = config["Crypt Limits"]
logger = logging.getLogger(__name__)
exp_func = lambda level: logger.isEnabledFor(level)

_ = create_translation.create(
    "generate_token",
    os.getenv("UTESLA_LOCALES_SERVICES") or \
    "services-locales"
    
)

def to_raw(regex):
    if not (isinstance(regex, str)):
        raise TypeError(_("La expresión regular no es un tipo de dato válido"))

    return regex.encode("unicode-escape").decode()

def is_regex(regex):
    try:
        re.compile(regex)

    except re.error:
        return False

    else:
        return True

class Handler:
    def __init__(self, password: str):
        self.password = password

        self.token_len = crypt_limits["token_length"]
        self.time_cost = crypt_limits["time_cost"]
        self.memory_cost = crypt_limits["memory_cost"]
        self.parallelism = crypt_limits["parallelism"]

    @property
    def SUPPORTED_METHODS(self):
        return ("generate", "change_services", "change_passwd", "renew")

    @property
    def NO_TOKEN_REQUIRED(self):
        return ("generate", "change_passwd")

    def SET_CONTROLLER(self, controller, /):
        self.controller = controller
        self.template = controller.template
        self.template.set_function_expression(exp_func)
        self.get_template = self.template.get_template

    async def INITIALIZER(self):
        if (self.controller.request.is_guest_user):
            logger.warning(
                _("%s: El usuario es un invitado; necesita un token de un usuario administrador"),
                self.get_template(logging.WARNING)
                
            )
            
            await self.controller.write_status(errno.EPERM)
            return False

        hash2text = await self.controller.pool.return_first_result(
            "get_password", self.controller.request.userid

        )

        if (hash2text is None):
            logger.error(
                _("%s: ¡No se pudo obtener el hash!"),
                self.get_template(logging.ERROR)
                
            )

            await self.controller.write_status(errno.ESERVER)
            return False

        else:
            (hash2text,) = hash2text

        try:
            verify_hash.verify(hash2text, self.password)

        except argon2.exceptions.InvalidHash:
            logger.error(
                _("%s: ¡El hash obtenido de la base de datos es inválido!"),
                self.get_template(logging.ERROR)
                
            )

            await self.controller.write_status(errno.ESERVER)
            return False

        except argon2.exceptions.VerifyMismatchError:
            logger.error(
                _("%s: La contraseña proporcionada no es correcta"),
                self.get_template(logging.ERROR)
                
            )

            await self.controller.write_status(
                errno.EPERM, _("La contraseña proporcionada no es correcta")

            )
            return False

        return True

    @staticmethod
    async def is_regex(regex):
        if not (is_regex(regex)):
            logger.error(
                _("%s: Se debe usar una expresión regular válida"),
                self.get_template(logging.ERROR)
                
            )

            await self.controller.write_status(errno.ECLIENT, _("La expresión regular no es válida"))
            return False

        return True

    async def change_services(self, services: str):
        services = to_raw(services)

        if not (await self.is_regex(services)):
            return

        token = self.controller.pool.callback.token2hash(self.controller.request.token)

        await self.controller.pool.return_first_result("change_services", token, services)
        await self.controller.write_status(0)

    async def change_passwd(
        self,
        new_password: str,
        token_limit: int = None
        
    ):
        logger.warning(_("%s: ¡Cambiando contraseña!"), self.get_template(logging.WARNING))

        pass2hash = generate_hash.generate(
            new_password,
            self.time_cost,
            self.memory_cost,
            self.parallelism

        )

        await self.controller.pool.return_first_result(
            "change_password", pass2hash, self.controller.request.userid
        
        )
        
        if (token_limit is not None):
            logger.warning(_("%s: Cambiando el límite de token's"), self.get_template(logging.WARNING))

            await self.controller.pool.return_first_result(
                "change_token_limit", token_limit, self.controller.request.userid
                
            )

        logger.info(_("%s: Hecho."), self.get_template(logging.INFO))

        await self.controller.write_status(0)

    async def renew(self):
        token = self.controller.pool.callback.token2hash(self.controller.request.token)
        
        new_token = await self.controller.pool.return_first_result(
            "renew_token", token, self.token_len
                
        )

        await self.controller.write(new_token)

    async def generate(
        self,
        expire: int,
        services: str = "(.*)"
        
    ):
        services = to_raw(services)

        if (expire <= 0):
            logger.error(
                _("%s: Los segundos de expiración deben ser mayor que 0"),
                self.get_template(logging.ERROR)
                
            )

            await self.controller.write_status(errno.ECLIENT, _("Los segundos de expiración deben ser mayor que 0"))
            return

        if not (await self.is_regex(services)):
            return

        logger.debug(_("%s: Generando e insertando token..."), self.get_template(logging.DEBUG))

        try:
            token = await self.controller.pool.return_first_result(
                "insert_token", self.controller.request.userid, expire, services, self.token_len

            )

        except exceptions.TokenLimitsExceeded:
            await self.controller.write_status(errno.ETOKLIMIT)

            logger.debug(_("%s: Se ha llegado al límite de token's permitidos"), self.get_template(logging.DEBUG))

        else:
            logger.info(_("%s: ¡Se ha creado un nuevo token!"), self.get_template(logging.INFO))
            logger.debug(_("%s: Enviando token..."), self.get_template(logging.DEBUG))

            await self.controller.write(token)
