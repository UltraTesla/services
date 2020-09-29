import os
import re
import logging

from modules.Infrastructure import errno
from utils.General import parse_config
from utils.General import show_services
from utils.extra import create_translation

config = parse_config.parse()
service_path = config["Server"]["services"]
admin_service = config["Server"]["admin_service"]
autoreload = config["Server"]["autoreload"]
logger = logging.getLogger(__name__)
exp_func = lambda level: logger.isEnabledFor(level)

_ = create_translation.create(
    "get_services",
    os.getenv("UTESLA_LOCALES_SERVICES") or \
    "services-locales"
    
)

class Handler:
    @property
    def SUPPORTED_METHODS(self):
        return "get"

    def SET_CONTROLLER(self, controller, /):
        self.controller = controller
        self.template = controller.template
        self.template.set_function_expression(exp_func)
        self.get_template = self.template.get_template
    
    async def get(self):
        regex = await self.controller.pool.return_first_result("get_services_allowed", self.controller.request.token_hash)

        if (regex is None):
            logger.warning(_(
                "No se pudo obtener la expresión regular que "
                "indica qué servicios están permitidos para "
                "este token de acceso."
                
            ))
            await self.controller.write_status(errno.ESERVER)
            return

        else:
            (regex,) = regex

        services = show_services.show(sub_service=False, only_name=True)
        remote_services = self.controller.pool.execute_command("get_services")

        logger.info(_("%s: Obteniendo los servicios..."), self.get_template(logging.INFO))
        logger.debug(_("%s: Obteniendo los servicios locales..."), self.get_template(logging.DEBUG))

        for service in services:
            if (service != admin_service) and (re.match(regex, service)):
                await self.controller.write(service)

        logger.debug(_("%s: Obteniendo los servicios remotos..."), self.get_template(logging.DEBUG))
        
        async for service in remote_services:
            (service,) = service
            service_name = os.path.join(service_path, service)
            
            # Si existen localmente significa que ya se compartieron
            if (re.match(regex, service)) and not (os.path.isdir(service_name)):
                await self.controller.write(service)

        await self.controller.write(None)
