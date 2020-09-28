import os
import logging

from utils.extra import create_translation

_ = create_translation.create(
    "index",
    os.getenv("UTESLA_LOCALES_SERVICES") or \
    "services-locales"
    
)

class Handler:
    @property
    def SUPPORTED_METHODS(self):
        return "get"

    def SET_CONTROLLER(self, controller, /):
        self.controller = controller

    async def get(self):
        await self.controller.write(_("¡Hola Mundo!"))
