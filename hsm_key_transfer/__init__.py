import base64
import secrets
import boto3
from ownca import CertificateAuthority
from .excrypt import ExcryptClient
from .utils import decode


# AWS Clients
boto_session = boto3.Session(profile_name='procde')
aws_sm = boto_session.client('secretsmanager')
aws_pc = boto_session.client('payment-cryptography')
def get_secret_value(name):
    secret = aws_sm.get_secret_value(SecretId=name)
    return secret.get('SecretString', secret.get('SecretBinary'))

# Excrypt Client
p12_cert = get_secret_value('virtucrypt_p12_cert')
p12_password = get_secret_value('virtucrypt_p12_password')
ex = ExcryptClient(p12_cert, p12_password)



class AWS:
    @staticmethod
    def get_virtucrypt_bdk():
        return get_secret_value('virtucrypt_bdk_tr31')

    @staticmethod
    def generate_krd_cert():
        print('\nGenerate Key Receiving Device (KRD) cert at AWS...')

        response = aws_pc.get_parameters_for_import(
            KeyMaterialType='TR34_KEY_BLOCK',
            WrappingKeyAlgorithm='RSA_2048',
        )
        print(f'\nGENERATE KRD | RESPONSE: {response}')
        token = response.get('ExportToken')
        cert_chain = base64.b64decode(response.get('WrappingKeyCertificateChain')) # KRD cert chain in PEM format
        cert = base64.b64decode(response.get('WrappingKeyCertificate')) # KRD cert in PEM format
        nonce = secrets.token_hex(8)
        return token, cert_chain, cert, nonce

    @staticmethod
    def __import_key(payload):
        print(f'\nIMPORT KEY | REQUEST: {payload}')
        response = aws_pc.import_key(payload)
        print(f'IMPORT KEY | RESPONSE: {response}')
        return response.get('Key').get('KeyArn')

    @staticmethod
    def __import_kdh_ca_cert(kdh_ca_cert):
        payload = dict(
            KeyMaterial=dict(
                RootCertificatePublicKey=dict(
                    KeyAlgorithm='RSA_2048',
                    KeyClass='PUBLIC_KEY',
                    KeyModesOfUse=dict(Verify=True),
                    KeyUsage='TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE',
                )
            ),
            PublicKeyCertificate=kdh_ca_cert,
        )
        return __class__.__import_key(payload)

    @staticmethod
    def import_kek(krd_token, krd_nonce, kdh_ca_cert, kdh_cert, kek):
        print('\nImport KEK to AWS...')

        kdh_ca_cert_arn = __class__.__import_kdh_ca_cert(kdh_ca_cert)
        payload = dict(
            KeyMaterial=dict(
                Tr34KeyBlock=dict(
                    CertificateAuthorityPublicKeyIdentifier=kdh_ca_cert_arn,
                    ImportToken=krd_token,
                    KeyBlockFormat='X9_TR34_2012',
                    RandomNonce=krd_nonce,
                    SigningKeyCertificate=kdh_cert,
                    WrappedKeyBlock=kek,
                )
            )
        )
        return __class__.__import_key(payload)

    @staticmethod
    def import_bdk_under_kek(kek_arn, bdk_under_kek):
        print('\nImport BDK to AWS...')

        payload = dict(
            KeyMaterial=dict(
                Tr31KeyBlock=dict(
                    WrappedKeyBlock=bdk_under_kek,
                    WrappingKeyIdentifier=kek_arn,
                )
            )
        )
        return __class__.__import_key(payload)


class Futurex:
    @staticmethod
    def __generate_kdh_ca_cert():
        def to_pem(cert):
            return cert.cert_bytes.decode('utf-8').replace('\n', '')

        # Generate root CA for signing KDH cert
        root_ca = CertificateAuthority(
            ca_storage='./CA',
            common_name='TR34 Export CA',
        )
        root_ca_cert = to_pem(root_ca)
        print('\nKDH Root CA cert:', root_ca_cert)

        # Issue KDH cert signed by root CA
        ca_cert = root_ca.issue_certificate(
            hostname='tr34-export-ca',
        )
        ca_cert = to_pem(ca_cert)
        print('\nKDH CA cert:', ca_cert)

        return ca_cert

    @staticmethod
    def __generate_kdh_keys():
        # Generate RSA Keys for KDH
        GRSA_response = ex.send({
            'AO': 'GRSA',
            'RA': '10001', # Public Exponent to be generated (typically 10001)
            'RB': '2048',  # Public Modulus Size (typically 2048 for financial keys)
            'RC': 'NONE',  # NONE = Return the private key (encrypted) instead of storing it in the key table
            # 'RC': '2',     # key table index
            'BJ': '6',     # 6 = Use PMK for encryption
            'KB': '1',     # 1 = Use ANSI Key Block
            'CZ': 'S',     # S = Usage: Asymmetric Sign & Verify
        })
        private_key = GRSA_response.get('RC') # Private Key (encrypted)
        public_key = GRSA_response.get('RD') # Clear Public Key in DER format
        return private_key, public_key

    @staticmethod
    def __generate_kdh_csr(private_key):
        RSAR_response = ex.send({
            'AO': 'RSAR',
            'RC': private_key,   # Encrypted Private Key used to generate the signature
            'RR': 'SeamlessPay', # org name
            'RT': 'TR34 Export', # common name
            'RG': '4',           # 4 = Use SHA256
            'FS': '6',           # 6 = Major key to use for encryption: PMK
        })
        return RSAR_response.get('RU') # PKCS #10 cert in DER format

    @staticmethod
    def generate_kdh_cert():
        print('\nGenerate Key Distribution Host (KDH) cert at Futurex...')

        kdh_ca_cert = __class__.__generate_kdh_ca_cert()
        kdh_ca_cert_der = ex.convert_pem_to_der(kdh_ca_cert)
        kdh_private_key, kdh_public_key = __class__.__generate_kdh_keys()
        kdh_csr = __class__.__generate_kdh_csr(kdh_private_key)

        RSSR_response = ex.send({
            'AO': 'RSSR',
            'FS': '6',             # 6 = Major key used for encryption: PMK
            'RY': '3',             # 3 = Output certificate format: X.509
            'RC': kdh_private_key, # Private Signing Key under modifier 0 of Major Key specified in token FS
            'RH': kdh_ca_cert_der, # X.509 CA Issuer Certificate
            'RU': kdh_csr,         # PKCS #10 Certificate Signing Request
        })
        kdh_cert = RSSR_response.get('RV') # X.509 cert
        return kdh_ca_cert, kdh_cert, kdh_public_key

    @staticmethod
    def import_krd_cert(krd_cert_chain):
        print('\nImport KRD cert to Futurex...')

        # Import the KRD Root CA under dual control to get a Trusted Public Key
        krd_cert_chain = ex.convert_pem_to_der(krd_cert_chain)
        AVPC_response = ex.send({
            'AO': 'AVPC',
            'FS': '6',            # 6 = Use PMK for encryption
            'RY': '3',            # 3 = X.509 cert type
            'KB': '1',            # 1 = Use ANSI Key Block
            'CZ': 'S',            # S = Usage: Asymmetric Sign & Verify
            'RV': krd_cert_chain, # X.509 cert in DER format
        })
        status = AVPC_response.get('BB') # Certificate Validation Status
        if status == 'Y':
            return AVPC_response.get('RD') # Trusted Public Key (encrypted)
        else:
            raise Exception(f'KRD cert validation failed! | Response: {AVPC_response}')

    @staticmethod
    def __generate_kek():
        # Generate a TDES KEK (usage: Encyrpt/Decrypt)
        kek_header = 'D0000K0TB00E0000' # this correlates with the key type/modifier
        GPGS_response = ex.send({
            'AO': 'GPGS',
            'CT': '3',        # 3 = KEK??? (Key type to generate)
            'FS': '6',        # 6 = PMK??? (Major key that output will be under (default=PMK))
            'AK': kek_header, # Key block header of the outgoing key
        })
        kek = GPGS_response.get('BG') # Cryptogram of key under major key
        return kek, kek_header

    @staticmethod
    def generate_and_export_kek(kdh_cert, kdh_private_key, krd_cert, krd_public_key, krd_nonce):
        print('\nGenerate and export KEK from Futurex...')

        kek, kek_header = __class__.__generate_kek()
        TRTP_response = ex.send({
            'AO': 'TRTP',
            'ZA': '3',             # 3 = Diebold TR-34 Format
            'BJ': krd_nonce,       # Nonce issued by KRD
            'FS': '6',             # 6 = major key (PKI): PMK
            'RV': kdh_cert,        # KDH certificate
            'RC': kdh_private_key, # KDH private key encrypted by major key
            'SJ': krd_cert,        # KRD certificate
            'SA': krd_public_key,  # KRD CA trusted public key encrypted by major key
            'BG': kek,             # Symmetric key to RKL encrypted by major key
            'MK': '6',             # 6 = major key (symmetric): PMK
            'AK': kek_header,      # Static header to use. By default this is generated from token BG. It must match usage.
        })
        return decode(TRTP_response.get('SJ')) # KEK in Diebold TR-34 Format

    @staticmethod
    def export_bdk_under_kek(kek, bdk_under_pmk):
        print('\nExport BDK from Futurex...')

        bdk_under_pmk = AWS.get_virtucrypt_bdk()
        TWKD_response = ex.send({
            'AO': 'TWKD',
            'FS': '6',           # 6 = Major key: PMK
            'AP': kek,           # Key Encryption Key
            'BG': bdk_under_pmk, # Key to translate,
            'OF': "T",           # T = Output key format: TR-31
        })
        return decode(TWKD_response.get('BH')) # Working key encrypted under specified modifier of KEK




#-------------------------------------------------------------------------------

def main():
    krd_token, krd_cert_chain, krd_cert, krd_nonce = AWS.generate_krd_cert()

    kdh_ca_cert, kdh_cert, kdh_private_key = Futurex.generate_kdh_cert()

    # krd_public_key = Futurex.import_krd_cert(krd_cert_chain)
    # kek = Futurex.generate_and_export_kek(kdh_cert, kdh_private_key, krd_cert, krd_public_key, krd_nonce)
    # kek_arn = AWS.import_kek(krd_token, krd_nonce, kdh_ca_cert, kdh_cert, kek)

    # bdk_under_pmk = AWS.get_virtucrypt_bdk()
    # bdk_under_kek = Futurex.export_bdk_under_kek(kek, bdk_under_pmk)
    # bdk_arn = AWS.import_bdk_under_kek(kek_arn, bdk_under_kek)
