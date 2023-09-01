import binascii

import logging
logging.basicConfig()
logger = logging.getLogger()

def decode(encoded_data):
    logger.debug(f'hex-encoded data (ascii): {encoded_data}')
    binary_data = binascii.a2b_hex(encoded_data)
    logger.debug(f'hex-encoded data (binary): {binary_data}')
    decoded_data = binary_data.decode('utf-8')
    logger.debug(f'decoded data: {decoded_data}')
    decoded_data = decoded_data.replace('\x00', '') # remove padding
    return decoded_data
