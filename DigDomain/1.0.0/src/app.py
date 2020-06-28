import socket
import asyncio
import time
import random
import json
import ipaddress


from walkoff_app_sdk.app_base import AppBase

class Tools(AppBase):
    """
    An example of a Walkoff App.
    Inherit from the AppBase class to have Redis, logging, and console logging set up behind the scenes.
    """
    __version__ = "1.0.0"
    app_name = "Dig Domain"  # this needs to match "name" in api.yaml for WALKOFF to work

    def __init__(self, redis, logger, console_logger=None):
        """
        Each app should have this __init__ to set up Redis and logging.
        :param redis:
        :param logger:
        :param console_logger:
        """
        super().__init__(redis, logger, console_logger)


    async def dig_domains(self, domains):
        domain_names = domains.splitlines()
        output_dig=[]
        for domain in domain_names:
            dns=socket.gethostbyname_ex(domain.strip())[2]
            for dig in dns:
                try:
                    ip=ipaddress.ip_address(dig)
                    output_dig.append(domain + " #~# " + str(ip))
                except:
                    pass
        return str("\n".join(output_dig))

if __name__ == "__main__":
    asyncio.run(Tools.run(), debug=True)
