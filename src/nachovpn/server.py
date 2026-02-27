from nachovpn.core.request_handler import VPNStreamRequestHandler
from nachovpn.core.plugin_manager import PluginManager
from nachovpn.core.cert_manager import CertManager
from nachovpn.core.db_manager import DBManager
from nachovpn.plugins import VPNPlugin
from nachovpn.core.packet_handler import PacketHandler
from nachovpn.core.smb_manager import SMBManager

import nachovpn.plugins
import logging
import inspect
import socket
import socketserver
import os
import sys
import threading
import asyncio
import argparse

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s - [%(module)s.%(funcName)s]'
)

class ThreadedVPNServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, RequestHandlerClass, cert_manager, plugin_manager, use_tls=True):
        self.cert_manager = cert_manager
        self.plugin_manager = plugin_manager
        super().__init__(server_address, RequestHandlerClass)
        if use_tls:
            self.socket = cert_manager.ssl_context.wrap_socket(self.socket, server_side=True)

class VPNServer:
    def __init__(self, host='0.0.0.0', port=443, tls=True, cert_dir=os.path.join(os.getcwd(), 'certs')):
        self.host = host
        self.port = port
        self.tls = tls

        # Setup certificates
        self.cert_manager = CertManager(cert_dir)
        self.cert_manager.setup()

        # Initialize database
        self.db_manager = DBManager()

        # Start SMB server
        self.smb_manager = SMBManager()

        # Setup plugin manager with cert hash
        self.plugin_manager = PluginManager()

        # Common plugin kwargs
        plugin_kwargs = {
            'write_pcap': os.getenv("WRITE_PCAP", False),
            'cert_manager': self.cert_manager,
            'external_ip': os.getenv('EXTERNAL_IP', socket.gethostbyname(socket.gethostname())),
            'dns_name': os.getenv('SERVER_FQDN') or os.getenv('WEBSITE_HOSTNAME', socket.gethostname()),
            'db_manager': self.db_manager,
        }

        # Create PacketHandler
        self.packet_handler = PacketHandler(write_pcap=plugin_kwargs['write_pcap'])
        plugin_kwargs['packet_handler'] = self.packet_handler
        self.plugin_manager.packet_handler = self.packet_handler

        # Register plugins
        for name, plugin in inspect.getmembers(nachovpn.plugins, inspect.isclass):
            if issubclass(plugin, VPNPlugin) and plugin != VPNPlugin:
                self.plugin_manager.register_plugin(plugin, **plugin_kwargs)

        # Allow reuse of the address
        socketserver.ThreadingTCPServer.allow_reuse_address = True

        # Set packet handler
        self._packet_handler_thread = None
        self._packet_handler_loop = None

    def _start_packet_handler(self):
        def run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._packet_handler_loop = loop
            loop.run_until_complete(self.packet_handler.start())
            loop.run_forever()

        self._packet_handler_thread = threading.Thread(target=run, daemon=True)
        self._packet_handler_thread.start()

    def _stop_packet_handler(self):
        if self._packet_handler_loop:
            self._packet_handler_loop.call_soon_threadsafe(self._packet_handler_loop.stop)
        if self._packet_handler_thread:
            self._packet_handler_thread.join(timeout=5)

    def run(self):
        # Start PacketHandler
        self._start_packet_handler()
        try:
            with ThreadedVPNServer(
                (self.host, self.port),
                VPNStreamRequestHandler,
                self.cert_manager,
                self.plugin_manager,
                self.tls
            ) as server:
                logging.info(f"Server listening on {self.host}:{self.port}")
                server.serve_forever()
        finally:
            self._stop_packet_handler()

def main():
    parser = argparse.ArgumentParser(description='NachoVPN Server')
    parser.add_argument('--port', type=int, default=443, help='Port to listen on (default: 443)')
    parser.add_argument('--no-tls', dest='tls', action='store_false', help='Disable TLS encryption (default: enabled)')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--cert-dir', default=os.path.join(os.getcwd(), 'certs'), help='Certificate directory (default: ./certs)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('-q', '--quiet', action='store_true', help='Enable quiet logging (warnings only)')

    args = parser.parse_args()

    # Set log level
    log_level = logging.INFO
    if args.debug:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.WARNING

    logging.getLogger().setLevel(log_level)

    server = VPNServer(host=args.host, port=args.port, tls=args.tls, cert_dir=args.cert_dir)
    try:
        server.run()
    except KeyboardInterrupt:
        logging.info("\nShutting down...")

if __name__ == '__main__':
    main()