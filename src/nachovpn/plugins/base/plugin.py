from flask import Flask, jsonify
from jinja2 import Environment, FileSystemLoader
import logging
import os

class VPNPlugin:
    def __init__(self, cert_manager=None, external_ip=None, dns_name=None, db_manager=None, template_dir=None, packet_handler=None, **kwargs):
        self.enabled = True
        self.cert_manager = cert_manager
        self.external_ip = external_ip
        self.dns_name = dns_name
        self.db_manager = db_manager
        self.template_dir = template_dir
        self.packet_handler = packet_handler
        self.logger = logging.getLogger(self.__class__.__name__)

        # setup Flask app
        self.flask_app = Flask(__name__)
        self._setup_routes()

        # Set up Jinja2 environment if template_dir is provided
        default_dir = os.path.join(os.path.dirname(__file__), 'templates')
        if template_dir:
            self.template_env = Environment(loader=FileSystemLoader([template_dir, default_dir]))
        else:
            self.template_env = Environment(loader=FileSystemLoader(default_dir))

    def is_enabled(self):
        return self.enabled

    def get_thumbprint(self):
        thumbprint = self.cert_manager.server_thumbprint
        if os.getenv('USE_DYNAMIC_SERVER_THUMBPRINT', 'false').lower() == 'true':
            dynamic_thumbprint = self.cert_manager.get_thumbprint_from_server(self.dns_name)
            if dynamic_thumbprint:
                self.logger.debug(f"Using dynamic thumbprint for {self.dns_name}: {dynamic_thumbprint}")
                thumbprint = dynamic_thumbprint
        return thumbprint

    def _setup_routes(self):
        # Define Flask routes within the class
        @self.flask_app.route('/api/v1/healthcheck', methods=['GET'])
        def healthcheck():
            return jsonify({"message": "OK"})

        @self.flask_app.errorhandler(404)
        def page_not_found(e):
            return self.render_template('404.html'), 404

    def _send_flask_response(self, response, handler):
        # Send the Flask response back to the client
        handler.send_response(response.status_code)
        for header, value in response.headers:
            handler.send_header(header, value)
        handler.end_headers()
        handler.wfile.write(response.data)

    def handle_get(self, handler):
        with self.flask_app.test_client() as client:
            response = client.get(handler.path, headers=dict(handler.headers))
            self._send_flask_response(response, handler)
        return True

    def handle_post(self, handler):
        content_length = int(handler.headers.get('Content-Length', 0))
        body = handler.rfile.read(content_length)

        # Use Flask's test_client to handle the request
        with self.flask_app.test_client() as client:
            response = client.post(handler.path, data=body, headers=dict(handler.headers))
            self._send_flask_response(response, handler)
        return True

    def render_template(self, template_name, **context):
        """Render a template with the given context"""
        if not hasattr(self, 'template_env'):
            raise Exception("No template environment configured")
        template = self.template_env.get_template(template_name)
        return template.render(**context)

    def can_handle_data(self, data, client_socket, client_ip):
        """Check if this plugin can handle the given data"""
        return False

    def can_handle_http(self, handler):
        """Determine if this plugin can handle the HTTP request"""
        return False

    def handle_data(self, data, client_socket, client_ip):
        return False

    def handle_http(self, handler):
        if handler.command == 'GET':
            return self.handle_get(handler)
        elif handler.command == 'POST':
            return self.handle_post(handler)
        return False

    def log_credentials(self, username, password, other_data=None):
        """Helper method to log credentials to the database."""
        if self.db_manager:
            self.db_manager.log_credentials(
                username=username,
                password=password,
                plugin_name=self.__class__.__name__,
                other_data=other_data
            )

    def _wrap_packet(self, packet_data, client):
        """Wrap the packet data with the plugin's specific protocol."""
        return packet_data