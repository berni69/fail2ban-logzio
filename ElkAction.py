#!/usr/bin/env python
import json
import logging
import socket
import sys
import traceback

import requests
import shodan
from fail2ban.server.actions import ActionBase


class ElkAction(ActionBase):
    def __init__(self, jail, name, shodan_token, logzio_token):
        super(ElkAction, self).__init__(jail, name)
        self.SHODAN_API_KEY = shodan_token
        self.LOGZIO_TOKEN = logzio_token
        self.jail = jail
        self.name = name

    def start(self):
        pass

    def stop(self):
        pass

    def ban(self, aInfo):
        ip = str(aInfo["ip"])
        data = {'src': ip}
        try:
            shodan_api = shodan.Shodan(self.SHODAN_API_KEY)
            host_info = shodan_api.host(ip)
            host_info['error_type'] = 'NoError'
        except shodan.exception.APIError:
            host_info = {'error_msg': "No info available for, IP  " + ip + " for jail " + self._jail.name,
                         'error_type': 'APIError'}
            self._logSys.info(
                "No info available for, IP %s for jail '%s'",
                ip, self._jail.name)
        except Exception as e:
            host_info = {'error_msg': e.message, 'error_type': 'generic'}
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self._logSys.error(traceback.format_exc())
            self._logSys.error(
                "Error getting info from SHODAN, IP %s for jail '%s'. Exception line(%d): %s",
                ip, self._jail.name, exc_tb.tb_lineno, e,
                exc_info=self._logSys.getEffectiveLevel() <= logging.DEBUG)
        # Try to geoloc only
        if host_info['error_type'] == 'APIError':

            r = requests.get("https://tools.keycdn.com/geo.json?host=" + ip)
            result = r.json()
            if result['status'] == 'success':
                latitude = result['data']['geo']['latitude']
                longitude = result['data']['geo']['longitude']
                data['location2'] = [longitude, latitude]
            else:
                self._logSys.error("Error getting geolocation info from keycdn. IP %s", ip)
        try:
            logger = r'https://listener.logz.io:8071/?token=' + self.LOGZIO_TOKEN + r'&type=fail2ban'
            if host_info['error_type'] == 'NoError':
                host_data = host_info['data']
                latitude = host_data[0]['location']['latitude']
                longitude = host_data[0]['location']['longitude']
                data['location2'] = [longitude, latitude]
                services = {}
                for service in host_data:
                    if "ssl" in service:
                        service['ssl']['cert']['serial'] = str(service['ssl']['cert']['serial'])

                    if "product" in service:
                        services[service['product']] = service
                    else:
                        services[service['port']] = service
                host_info.pop('data', None)
                data['services'] = services
            data['dst'] = socket.gethostname()
            data['shodan'] = host_info
            requests.post(logger, data=json.dumps(data))
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self._logSys.error(traceback.format_exc())
            self._logSys.error(
                "Error sending info to logz.io, IP %s for jail '%s'. Exception line(%d): %s",
                ip, self._jail.name, exc_tb.tb_lineno, e,
                exc_info=self._logSys.getEffectiveLevel() <= logging.DEBUG)

    def unban(self, aInfo):
        pass


Action = ElkAction
