load("@stdlib//base64", b64decode="b64decode", b64encode="b64encode")
load("@stdlib//binascii", hexlify="hexlify", unhexlify="unhexlify")
load("@stdlib//larky", larky="larky")
#load("@stdlib//japplepay", _applepay="japplepay")

load("@vendor//Crypto/Hash/SHA256", SHA256="SHA256")
load("@vendor//cryptography/x509", load_pem_x509_certificate="load_pem_x509_certificate")
load("@vendor//Crypto/Cipher/AES", AES="AES")

OID_MERCHANT_ID = "1.2.840.113635.100.6.32"
OID_LEAF_CERTIFICATE = "1.2.840.113635.100.6.29"
OID_INTERMEDIATE_CERTIFICATE = "1.2.840.113635.100.6.2.14"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"

def Payment(merc_ca_pem, private_key_pem, root_ca_der=None, aai_ca_der=None):
    self = larky.mutablestruct(__name__="Payment", __class__=Payment)
    def __init__(merc_ca_pem, private_key_pem, root_ca_der=None, aai_ca_der=None):
        """
        backend = default_backend()
        if root_ca_der is None:
            self._root_ca = load_der_x509_certificate(open(ROOT_CA_FILE, 'rb').read(), backend)
        else:
            self._root_ca = load_der_x509_certificate(root_ca_der, backend)

        if aai_ca_der is None:
            self._aai_ca = load_der_x509_certificate(open(AAI_CA_FILE, 'rb').read(), backend)
        else:
            self._aai_ca = load_der_x509_certificate(aai_ca_der, backend)

        merc_ca = load_pem_x509_certificate(merc_ca_pem, backend)

        self._validate_cert(merc_ca)

        self._merc_id = unhexlify(self._extract_merchant_id(merc_ca))
        self._private_key = load_pem_private_key(private_key_pem, None, backend)
        """
        self.merc_ca_pem = merc_ca_pem
        self.private_key_pem = private_key_pem
        return self
    self = __init__(merc_ca_pem, private_key_pem, root_ca_der=None, aai_ca_der=None)

    def _validate_cert(merc_ca):
        return True

    def _valid_signature(ephemeral_public_key, data, transaction_id, application_data=''):
        """
        s = b64decode(ephemeral_public_key) + b64decode(data) + b64decode(transaction_id) + b64decode(application_data)
        return self._private_key.sign(s, ec.ECDSA(hashes.SHA256()))
        """
        return True

    def _extract_merchant_id(cert_pem):
        
        for ext in cert_pem.extensions:
            if ext.oid.dotted_string == OID_MERCHANT_ID:
                return ext.value.value[2:]
        

        return None

    def _generate_symmetric_key(shared_secred, _merc_id):
    
        sha = SHA256.new()
        sha.update(b'\0' * 3)
        sha.update(b'\1')
        sha.update(shared_secred)
        sha.update(b'\x0did-aes256-GCM' + b'Apple' + _merc_id)

        return sha.digest()
        

    def decrypt(ephemeral_public_key, cipher_data, transaction_id=None, application_data=''):

        # public_key = load_der_public_key(b64decode(ephemeral_public_key), default_backend())
        cipherdata = b64decode(cipher_data)
        # shared_secret = self._private_key.exchange(ec.ECDH(), public_key)
        shared_secret = unhexlify(b'6b6a4f7de992740e7ad059f32d2bfccdf76559d1894e89c0a4e2ead737e0c7cc')
        merc_id = unhexlify(b'F938F4658CA2C1C9C38B8DFCB5DBB2A2245607DDE2F114620E8468EF52D208CA')
        symmetric_key = _generate_symmetric_key(shared_secret, merc_id)
        nonce = b'\0'*16
        cipher = AES.new(symmetric_key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(cipherdata[:-16],cipherdata[-16:])
        return decrypted

    def encrypt(ephemeral_public_key, plaintext, applicationData=None):

        # Encrypt plaintext
        shared_secret = unhexlify(b'6b6a4f7de992740e7ad059f32d2bfccdf76559d1894e89c0a4e2ead737e0c7cc')
        merc_id = unhexlify(b'F938F4658CA2C1C9C38B8DFCB5DBB2A2245607DDE2F114620E8468EF52D208CA')
        symmetric_key = _generate_symmetric_key(shared_secret, merc_id)
        nonce = b'\0' * 16
        cipher = AES.new(symmetric_key, AES.MODE_GCM, nonce=nonce)
        encrypted,tag = cipher.encrypt_and_digest(plaintext)
        encrypted_payload = encrypted+tag

        # Generate payload to return
        payment_json = {
            "version":"EC_v1",
            "data": b64encode(encrypted_payload).decode('utf-8'),
            "signature": "",
            "header": {
                "transactionId": "2686f5297f123ec7fd9d31074d43d201953ca75f098890375f13aed2737d92f2", # Do I do this?
                "ephemeralPublicKey": ephemeral_public_key,
                "publicKeyHash": "LbsUwAT6w1JV9tFXocU813TCHks+LSuFF0R/eBkrWnQ=" # Go back and look in the data for this actual value
            }
        }

        # Calculate Signature
        sig_string = b64decode(ephemeral_public_key) + b64decode(encrypted_payload)
        sig_string += unhexlify(payment_json['header']['transactionId'])
        if applicationData:
            sig_string += unhexlify(applicationData)

        return payment_json

    self.decrypt = decrypt
    self.encrypt = encrypt
    self._generate_symmetric_key = _generate_symmetric_key
    return self