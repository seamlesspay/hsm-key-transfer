import json
import requests_pkcs12
import ssl

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import logging
logging.basicConfig()
logger = logging.getLogger()

class ExcryptClient:
    endpoint = 'https://us01crypto01.virtucrypt.com:4265/guardian'

    def __init__(self, pkcs12_data, pkcs12_password, log_level='INFO') -> None:
        set_logging_level(log_level)
        self.pkcs12_data = pkcs12_data
        self.pkcs12_password = pkcs12_password

    def send(self, payload):
        headers = {
            "Content-Type": "application/json"
        }
        print(f'\nEXCRYPT | REQUEST: {payload}')
        response = requests_pkcs12.post(
            self.endpoint,
            json=payload,
            headers=headers,
            pkcs12_data=self.pkcs12_data,
            pkcs12_password=self.pkcs12_password,
            ssl_protocol=ssl.PROTOCOL_TLS,
            verify=False
        )
        # print(f'EXCRYPT | RESPONSE CODE: {response.status_code}')
        response_json = self.__get_response_json(response)
        print(f'EXCRYPT | RESPONSE: {response_json}')
        response.raise_for_status()
        if response_json.get('AO') == 'ERRO':
            raise Exception(f'Command "{payload.get("AO")}" failed with error message: {response_json.get("BB")}')
        return response_json

    def send_echo(self):
        return self.send({
            'AO': 'ECHO',
            'AK': 'hai',
        })

    def convert_pem_to_der(self, cert):
        RCCN_response = self.send({
            'AO': 'RCCN',
            'RN': '31', # 31 = convert PEM to DER
            'RY': '3',  # 3 = X.509 cert type
            'RT': cert,
        })
        return RCCN_response.get('RS') # X.509 cert in DER format

    def __get_response_json(self, response):
        try:
            return response.json()
        except json.decoder.JSONDecodeError:
            raise Exception(f'Cannot parse response body as JSON ({response.text})')


def set_logging_level(log_level):
    level = vars(logging).get(log_level)
    logger.setLevel(level)
    logging.getLogger('requests.packages.urllib3').setLevel(level)
    if level is logging.DEBUG:
        import http.client
        http.client.HTTPConnection.debuglevel = 1
