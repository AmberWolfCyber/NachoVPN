from impacket.smbserver import SimpleSMBServer
import os
import stat
import logging
import threading

# SMB configuration
SMB_ENABLED = os.getenv("SMB_ENABLED", "false").lower() == "true"
SMB_SHARE_NAME = os.getenv("SMB_SHARE_NAME", "SHARE")
SMB_SHARE_PATH = os.getenv("SMB_SHARE_PATH", "smb")

class SMBManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.server = None

        if SMB_ENABLED:
            self._setup_smb_server()

    def auth_callback(self, *args, **kwargs):
        """Authentication callback"""
        self.logger.debug(f"Authenticate message: {args} {kwargs}")
        return True

    def _setup_smb_server(self):
        """Set up the SMB server"""
        try:
            # Create share directory if it doesn't exist
            os.makedirs(SMB_SHARE_PATH, exist_ok=True)

            # Impacket's readOnly flag is not implemented, so make the directory read-only
            os.chmod(SMB_SHARE_PATH, stat.S_IREAD | stat.S_IEXEC)

            # Initialize SMB server
            self.server = SimpleSMBServer("0.0.0.0", 445)

            # Add share
            self.server.addShare(SMB_SHARE_NAME.upper(), SMB_SHARE_PATH, shareComment='Nacho SMB Share', readOnly='yes')

            # Enable SMBv2
            self.server.setSMB2Support(True)

            # Start SMB server in a separate thread
            smb_thread = threading.Thread(target=self.server.start, daemon=True)
            smb_thread.start()
            self.logger.info(f"Started SMB server with share '{SMB_SHARE_NAME}' at {SMB_SHARE_PATH}")
        except Exception as e:
            self.logger.error(f"Failed to start SMB server: {e}")
            self.server = None
