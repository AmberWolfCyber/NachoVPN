from nachovpn.plugins.pulse.funk_parser import FunkManager
from nachovpn.plugins.pulse.plugin import AVP, EAPPacket, IFTPacket, EXPANDED_JUNIPER, \
    JUNIPER_1, EAP_REQUEST, VENDOR_TCG, AVP_CODE_EAP_MESSAGE, IFT_CLIENT_AUTH_CHALLENGE

import os
import zlib
import logging
import difflib

logging.basicConfig(level=logging.DEBUG)

def hexdump(data: bytes):
    def to_printable_ascii(byte):
        return chr(byte) if 32 <= byte <= 126 else "."

    offset = 0
    while offset < len(data):
        chunk = data[offset : offset + 16]
        hex_values = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_values = "".join(to_printable_ascii(byte) for byte in chunk)
        print(f"{offset:08x}  {hex_values:<48}  |{ascii_values}|")
        offset += 16

def build_remediation_packet():
    outbuf = b''

    # EAP within AVP within EAP within IF-T/TLS
    outer_eap_data = b''
    outer_eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
    outer_eap_data += (1).to_bytes(4, 'big')

    # This is the EAP data encapsulated in AVP (which is itself encapsulated in EAP/IF-T/TLS)
    inner_eap_data = b''
    inner_eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
    inner_eap_data += (3).to_bytes(4, 'big')
    inner_eap_data += b'\x01' # no idea, maybe number of policies?

    # Build a host-checker policy with a registry command
    commands = FunkManager.remediation_command()
    policy = FunkManager.generate(commands)

    # Wrap it in an EAP request
    inner_eap_data += policy
    inner_eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=0x03, eap_data=inner_eap_data)

    # Build the AVP data from inner EAP data (without vendor)
    avp = AVP(code=0x4f, flags=0x40, value=inner_eap.to_bytes()[4:])

    # Add AVP data to outer EAP data
    outer_eap_data += avp.to_bytes(include_padding=True)
    print (f'Padding required: {avp.padding_required()}')

    # Construct outer EAP packet
    outer_eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=0x05, eap_data=outer_eap_data)

    # Build IFT packet
    reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=0x05, message_identifier=0x01FA, message_value=outer_eap.to_bytes())

    # Append to output buffer
    outbuf += reply.to_bytes()
    return outbuf

def build_policy():
    outbuf = b''

    # EAP within AVP within EAP within IF-T/TLS
    outer_eap_data = b''
    outer_eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
    outer_eap_data += (1).to_bytes(4, 'big')

    # This is the EAP data encapsulated in AVP (which is itself encapsulated in EAP/IF-T/TLS)
    inner_eap_data = b''
    inner_eap_data += EXPANDED_JUNIPER.to_bytes(4, 'big')
    inner_eap_data += (3).to_bytes(4, 'big')
    inner_eap_data += b'\x01' # no idea, maybe number of policies?

    # Build a host-checker policy with a registry command
    commands = FunkManager.registry_command()
    policy = FunkManager.generate(commands)

    # Wrap it in an EAP request
    inner_eap_data += policy
    inner_eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=0x02, eap_data=inner_eap_data)

    # Build the AVP data from inner EAP data (without vendor)
    avp = AVP(code=0x4f, flags=0x40, value=inner_eap.to_bytes()[4:])

    # Add AVP data to outer EAP data
    outer_eap_data += avp.to_bytes(include_padding=True)
    print (f'Padding required: {avp.padding_required()}')

    # Construct outer EAP packet
    outer_eap = EAPPacket(vendor=JUNIPER_1, code=EAP_REQUEST, identifier=0x04, eap_data=outer_eap_data)

    # Build IFT packet
    reply = IFTPacket(vendor_id=VENDOR_TCG, message_type=0x05, message_identifier=0x01F9, message_value=outer_eap.to_bytes())

    # Append to output buffer
    outbuf += reply.to_bytes()
    return outbuf

def compare(file_1, file_2):
    with open(file_1, 'rb') as f:
        example_bytes = f.read()

    with open(file_2, 'rb') as f:
        generated_data = f.read()

    # Diff generated data with example file
    bytes1 = list(example_bytes)
    bytes2 = list(generated_data)

    diff = difflib.unified_diff(
        [f"{b:02x}" for b in bytes1],
        [f"{b:02x}" for b in bytes2],
        lineterm=""
    )

    same = True
    for line in diff:
        print(line)
        same = False

    if same:
        print('> No differences found!')

def build_remediation():
    commands = FunkManager.remediation_command()
    return FunkManager.generate(commands)

def generate_example_files():
    os.makedirs(os.path.join(os.path.dirname(__file__), 'examples'), exist_ok=True)

    # generate example IF-T / host-checker policy
    client_policy_file = os.path.join(os.path.dirname(__file__), 'examples', 'client_policy_packet.bin')
    client_policy_data = bytearray()
    client_policy_data += bytes.fromhex('00 00 55 97 00 00 00 05 00 00 01 CC 00 00 01 F9')
    client_policy_data += bytes.fromhex('00 0A 4C 01 01 04 01 B8 FE 00 0A 4C 00 00 00 01')
    client_policy_data += bytes.fromhex('00 00 00 4F 40 00 01 A9 01 02 01 A1 FE 00 0A 4C')
    client_policy_data += bytes.fromhex('00 00 00 03 01 00 00 00 16 C0 00 01 93 00 00 05')
    client_policy_data += bytes.fromhex('83 00 00 02 78 78 9C 8D 52 CB 4A 03 31 14 8D 85')
    client_policy_data += bytes.fromhex('6E A4 0B 57 AE 87 F9 82 A6 D6 56 18 23 0C B5 52')
    client_policy_data += bytes.fromhex('B1 2F 5A 1F 28 C2 90 49 2E 35 3A 93 0C 49 A6 B5')
    client_policy_data += bytes.fromhex('D0 85 E0 8F F9 31 82 1F E0 0F 98 99 AA 88 14 34')
    client_policy_data += bytes.fromhex('AB 7B 0F 27 E7 9E 7B B8 08 D5 5E 5F 50 E5 0E A1')
    client_policy_data += bytes.fromhex('EA 33 42 B5 B7 17 84 2E CA BA FA BC 7B 38 0E 27')
    client_policy_data += bytes.fromhex('E1 C0 1B 86 83 2E F1 C7 54 D3 14 2C E8 BA EF 5D')
    client_policy_data += bytes.fromhex('86 FD 0B 07 05 0C B4 8D 52 BE 4F 02 03 7A 0E 3A')
    client_policy_data += bytes.fromhex('B2 22 05 82 DB 8D 36 3E 68 E3 46 CB 3F DA 46 E5')
    client_policy_data += bytes.fromhex('2B 74 2B 95 6F DD AC D0 F2 A4 D3 23 7E F6 A5 8B')
    client_policy_data += bytes.fromhex('7D 6F 4E 93 DC 41 2A BE 07 66 23 99 A7 31 68 82')
    client_policy_data += bytes.fromhex('03 2F D3 6A 2E B8 AB 35 CC 84 B1 7A 19 78 3A 4F')
    client_policy_data += bytes.fromhex('40 70 4C EA EB B2 D0 C2 64 A1 94 75 FD 27 29 7A')
    client_policy_data += bytes.fromhex('80 25 26 BD B3 EE 75 D4 1F 75 C2 7E 34 08 3B BD')
    client_policy_data += bytes.fromhex('D3 61 F7 07 C3 E4 71 49 9A 8E 4E CE AF C2 49 F7')
    client_policy_data += bytes.fromhex('B6 93 50 63 C0 DC D2 98 FD A0 6D 54 B7 CB CC 81')
    client_policy_data += bytes.fromhex('53 AB 85 9C 95 F0 A5 80 45 AB 89 0B C3 A9 90 2E')
    client_policy_data += bytes.fromhex('8E 6F 77 1A 52 E0 C4 80 FB 2E 01 B8 19 28 29 AC')
    client_policy_data += bytes.fromhex('2A 3E 16 64 B7 9F 4A 04 5B 92 39 AB AF 9A 7B AB')
    client_policy_data += bytes.fromhex('75 17 35 56 78 F5 6B 64 99 0F 26 AC C7 F3 9B 90')
    client_policy_data += bytes.fromhex('90 C0 8B A9 81 56 13 24 53 1C 5C 18 D8 05 BE 39')
    client_policy_data += bytes.fromhex('DC C6 3F C2 5D CF E5 D4 D2 BF 1D B9 A5 98 CA A5')
    client_policy_data += bytes.fromhex('2D 04 E0 31 D3 60 8C 50 F2 F4 D8 38 53 4C 49 2E')
    client_policy_data += bytes.fromhex('AC 6B 69 E2 02 F0 BD CF 23 A8 BD 3F 21 B4 B3 BE')
    client_policy_data += bytes.fromhex('33 B4 F5 01 ED 71 D0 C2 00 00 00 00')

    with open(client_policy_file, 'wb') as f:
        f.write(client_policy_data)

    # generate full remediation packet
    remediation_packet_file = os.path.join(os.path.dirname(__file__), 'examples', 'remediation_packet.bin')
    remediation_packet_data = bytearray()
    remediation_packet_data += bytes.fromhex('00 00 55 97 00 00 00 05 00 00 00 B8 00 00 01 FA')
    remediation_packet_data += bytes.fromhex('00 0A 4C 01 01 05 00 A4 FE 00 0A 4C 00 00 00 01')
    remediation_packet_data += bytes.fromhex('00 00 00 4F 40 00 00 95 01 03 00 8D FE 00 0A 4C')
    remediation_packet_data += bytes.fromhex('00 00 00 03 01 00 00 00 16 C0 00 00 7F 00 00 05')
    remediation_packet_data += bytes.fromhex('83 00 00 00 94 78 9C 63 60 E0 79 72 80 81 81 87')
    remediation_packet_data += bytes.fromhex('81 81 B5 19 48 7D 00 B2 33 A0 EC 8F 40 B6 00 88')
    remediation_packet_data += bytes.fromhex('5D 92 5A 5C C2 00 51 E7 03 95 7B 0E 64 DB 81 D9')
    remediation_packet_data += bytes.fromhex('AC CD 62 41 AE BE AE 2E 9E 8E 21 AE 56 01 FE 3E')
    remediation_packet_data += bytes.fromhex('9E CE 91 9E 2E B6 65 C9 06 35 26 C6 35 05 F9 39')
    remediation_packet_data += bytes.fromhex('99 C9 95 F1 46 35 86 35 E5 F9 F9 25 3A C5 A9 40')
    remediation_packet_data += bytes.fromhex('83 40 40 08 66 36 90 CD 08 34 EF 73 03 12 1F 00')
    remediation_packet_data += bytes.fromhex('25 39 21 7B 00')
    remediation_packet_data += bytes.fromhex('00 00 00') # padding (client sends A0 6D 9C)

    with open(remediation_packet_file, 'wb') as f:
        f.write(remediation_packet_data)

    # generate example remediation policy
    remediation_file = os.path.join(os.path.dirname(__file__), 'examples', 'remediation.bin')
    remediation_data = bytearray()
    remediation_data += bytes.fromhex('00 00 00 16 C0 00 00 7F 00 00 05 83 00 00 00 94')
    remediation_data += bytes.fromhex('78 9C 63 60 E0 79 72 80 81 81 87 81 81 B5 19 48')
    remediation_data += bytes.fromhex('7D 00 B2 33 A0 EC 8F 40 B6 00 88 5D 92 5A 5C C2')
    remediation_data += bytes.fromhex('00 51 E7 03 95 7B 0E 64 DB 81 D9 AC CD 62 41 AE')
    remediation_data += bytes.fromhex('BE AE 2E 9E 8E 21 AE 56 01 FE 3E 9E CE 91 9E 2E')
    remediation_data += bytes.fromhex('B6 65 C9 06 35 26 C6 35 05 F9 39 99 C9 95 F1 46')
    remediation_data += bytes.fromhex('35 86 35 E5 F9 F9 25 3A C5 A9 40 83 40 40 08 66')
    remediation_data += bytes.fromhex('36 90 CD 08 34 EF 73 03 12 1F 00 25 39 21 7B 00')

    with open(remediation_file, 'wb') as f:
        f.write(remediation_data)

    remediation_uncompressed_file = os.path.join(os.path.dirname(__file__), 'examples', 'remediation_uncompressed.bin')
    remediation_uncompressed_data = zlib.decompress(remediation_data[0x10:])

    with open(remediation_uncompressed_file, 'wb') as f:
        f.write(remediation_uncompressed_data)

# create example files
generate_example_files()

# build + test IF-T packet
client_policy_packet_file = os.path.join(os.path.dirname(__file__), 'generated_client_policy_packet.bin')
example_client_policy_packet = os.path.join(os.path.dirname(__file__), 'examples', 'client_policy_packet.bin')

data = build_policy()
print('\n> Generated client policy packet:')
hexdump(data)

with open(client_policy_packet_file, 'wb') as f:
    f.write(data)

print('\n> Comparing client policy packet with example:')
compare(example_client_policy_packet, client_policy_packet_file)

# Test remediation policy
remediation_file = os.path.join(os.path.dirname(__file__), 'generated_remediation.bin')
example_remediation = os.path.join(os.path.dirname(__file__), 'examples', 'remediation.bin')

# Uncompressed remediation policy
example_remediation_uncompressed = os.path.join(os.path.dirname(__file__), 'examples', 'remediation_uncompressed.bin')
remediation_uncompressed = os.path.join(os.path.dirname(__file__), 'generated_remediation_uncompressed.bin')

data = build_remediation()
print('\n> Generated remediation data:')
hexdump(data)

# write remediation data to file
with open(remediation_file, 'wb') as f:
    f.write(data)

# write uncompressed remediation data to file
with open(remediation_uncompressed, 'wb') as f:
    f.write(zlib.decompress(data[0x10:]))

print('\n> Comparing remediation data with example (uncompressed):')
compare(example_remediation_uncompressed, remediation_uncompressed)

print('\n> Comparing remediation data with example (compressed):')
compare(example_remediation, remediation_file)

# generate remediation full packet
remediation_packet_file = os.path.join(os.path.dirname(__file__), 'generated_remediation_packet.bin')
example_remediation_packet = os.path.join(os.path.dirname(__file__), 'examples', 'remediation_packet.bin')

data = build_remediation_packet()
print('\n> Generated remediation packet:')
hexdump(data)

with open(remediation_packet_file, 'wb') as f:
    f.write(data)

print('\n> Comparing remediation packet with example:')
compare(example_remediation_packet, remediation_packet_file)

# Cleanup
os.remove(client_policy_packet_file)
os.remove(remediation_file)
os.remove(remediation_uncompressed)
os.remove(remediation_packet_file)