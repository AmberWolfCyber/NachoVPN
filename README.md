# NachoVPN 🌮🔒

<p align="center">
    <img src="logo.png">
</p>

<p align="center">
    <a href="LICENSE" alt="License: MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" /></a>
</p>

NachoVPN is a Proof of Concept that demonstrates exploitation of SSL-VPN clients, using a rogue VPN server.

It uses a plugin-based architecture so that support for additional SSL-VPN products can be contributed by the community. It currently supports various popular corporate VPN products, such as Cisco AnyConnect, SonicWall NetExtender, Palo Alto GlobalProtect, and Ivanti Connect Secure.

For further details, see our [blog post](https://blog.amberwolf.com/blog/2024/november/introducing-nachovpn---one-vpn-server-to-pwn-them-all/), and HackFest Hollywood 2024 presentation [[slides](https://github.com/AmberWolfCyber/presentations/blob/main/2024/Very%20Pwnable%20Networks%20-%20HackFest%20Hollywood%202024.pdf)|[video](https://www.youtube.com/watch?v=-MZfkmcZRVg)].

## Installation

### Prerequisites

* Python 3.9 or later
* Docker (optional)
* osslsigncode (Linux only)
* msitools (Linux only)
* python-netfilter (Linux only)
* git

### Linux Setup

* Install `python3-netfilter` (on Ubuntu)
* Optionally use `setcap` to avoid `sudo` requirement:

  ```bash
  sudo setcap 'cap_net_raw,cap_net_bind_service,cap_net_admin=eip' /usr/bin/python3.10
  ```

* Enable IP forwarding:

  ```bash
  sudo sysctl -w net.ipv4.ip_forward=1
  ```

### Installing from source

NachoVPN can be installed from GitHub using pip. Note that this requires git to be installed.

First, create a virtual environment.

On Linux, ensure that the virtual env has access to the system `site-packages`, so that `nftables` works:

```bash
python3 -m venv env --system-site-packages
source env/bin/activate
```

On Windows, nftables (and thus packet forwarding) is disabled, so use:

```bash
python -m venv env
.\env\Scripts\activate
```

Then, install NachoVPN:

```bash
pip install git+https://github.com/AmberWolfCyber/NachoVPN.git
```

If you prefer to use Docker, then you can pull the container from the GitHub Container Registry:

```bash
docker pull ghcr.io/AmberWolfCyber/nachovpn:release
```

## Building for distribution

### Building a wheel file

First, clone this repository, and install `setuptools` and `wheel` via pip. You can then run the `setup.py` script:

```bash
git clone https://github.com/AmberWolfCyber/NachoVPN
pip install -U setuptools wheel
python setup.py bdist_wheel
```

This will generate a wheel file in the `dist` directory, which can be installed with pip:

```bash
pip install dist/nachovpn-1.0.0-py3-none-any.whl
```

### Building for local development

Alternatively, for local development you can install the package in editable mode using:

```bash
pip install -e .
```

### Building a container image

You can build the container image with the following command:

```bash
docker build -t nachovpn:latest .
```

## Running

To run the server as standalone, use:

```
python -m nachovpn.server
```

Alternatively, you can run the server using Docker:

```bash
docker run -e SERVER_FQDN=connect.nachovpn.local -e EXTERNAL_IP=1.2.3.4 -v ./certs:/app/certs -p 80:80 -p 443:443 --rm -it nachovpn
```

This will generate a certificate for the `SERVER_FQDN` using certbot, and save it to the `certs` directory, which we've mounted into the container.

Alternatively, for testing purposes, you can skip the certificate generation by setting the `SKIP_CERTBOT` environment variable.

This will generate a self-signed certificate instead.

```bash
docker run -e SERVER_FQDN=connect.nachovpn.local -e SKIP_CERTBOT=1 -e EXTERNAL_IP=1.2.3.4 -p 443:443 --rm -it nachovpn
```

An example [docker-compose file](docker-compose.yml) is also provided for convenience.

### Debugging

You can run `nachovpn` with the `-d` or `--debug` command line arguments in order to increase the verbosity of logging, which can aid in debugging.

Alternatively, if the logging is too noisy, you can use the `q` or `--quiet` command line argument instead.

### Plugins

NachoVPN supports the following plugins and capabilities:

| Plugin | Product | CVE | Windows RCE | macOS RCE | Privileged | URI Handler | Packet Capture | Demo |
| -------- | ----------- | -------- | -------- | -------- | -------- | -------- | -------- | ---- |
| Cisco | Cisco AnyConnect | N/A | ✅ | ✅ | ❌ | ❌ | ✅ | [Windows](https://vimeo.com/1024773762) / [macOS](https://vimeo.com/1024773668) |
| SonicWall | SonicWall NetExtender | [CVE-2024-29014](https://blog.amberwolf.com/blog/2024/november/sonicwall-netextender-for-windows---rce-as-system-via-epc-client-update-cve-2024-29014/) | ✅ | ❌ | ✅ | ✅ | ❌ | [Windows](https://vimeo.com/1024774407) |
| PaloAlto | Palo Alto GlobalProtect | [CVE-2024-5921](https://blog.amberwolf.com/blog/2024/november/palo-alto-globalprotect---code-execution-and-privilege-escalation-via-malicious-vpn-server-cve-2024-5921/) [(partial fix)](https://blog.amberwolf.com/blog/2025/august/nachovpn-update---palo-alto-globalprotect/) | ✅ | ✅ | ✅ | ❌ | ✅ | [Windows](https://vimeo.com/1024774239) / [macOS](https://vimeo.com/1024773987) / [iOS](https://vimeo.com/1024773956) |
| PulseSecure | Ivanti Connect Secure | [CVE-2020-8241 (bypassed)](https://blog.amberwolf.com/blog/2025/july/nachovpn-update---ivanti-connect-secure/) | ✅ | ✅ | ✅ | ✅ (Windows only - disabled by default in [22.8R1](https://help.ivanti.com/ps/help/en_US/ISAC/22.X/rn-22.X/noteworthy-information.htm)) | ✅ | [Windows](https://vimeo.com/1024773914) |
| Netskope | Netskope | [CVE-2025-0309](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/) | ✅ | ❌ | ✅ | ❌ | ❌ | [Windows](https://vimeo.com/1114191607) |

#### URI handlers

* The Ivanti Connect Secure (Pulse Secure) URI handler can be triggered by visiting the `/pulse` URL on the NachoVPN server.
* The SonicWall NetExtender URI handler can be triggered by visiting the `/sonicwall` URL on the NachoVPN server. This requires that the SonicWall Connect Agent is installed on the client machine.

#### Operating Notes

* It is recommended to use a TLS certificate that is signed by a trusted Certificate Authority. The docker container automates this process for you, using certbot. If you do not use a trusted certificate, then NachoVPN will generate a self-signed certificate instead, which in most cases will either cause the client to prompt with a certificate warning, or it will refuse to connect unless you modify the client settings to accept self-signed certificates. For the Palo Alto GlobalProtect plugin, this will also cause the MSI installer to fail.
* In order to simulate a valid codesigning certificate for the SonicWall plugin, NachoVPN will sign the `NACAgent.exe` payload with a self-signed certificate. For testing purposes, you can download and install this CA certificate from `/sonicwall/ca.crt` before triggering the exploit. For production use-cases, you will need to obtain a valid codesigning certificate from a public CA, sign your `NACAgent.exe` payload, and place it in the `payloads` directory (or volume mount it into `/app/payloads`, if using docker).
* For convenience, a default `NACAgent.exe` payload is generated for the SonicWall plugin, and written to the `payloads` directory. This simply spawns a new `cmd.exe` process on the current user's desktop, running as `SYSTEM`.
* The Palo Alto GlobalProtect plugin requires that the MSI installers and `msi_version.txt` file are present in the `downloads` directory. Either add these manually, or run the `msi_downloader.py` script to download them.
* To perform the Palo Alto GlobalProtect downgrade attack, ensure that the `GlobalProtect.msi.old` and `GlobalProtect64.msi.old` are present in the `downloads` folder. These files should contain the *unmodified* MSI installers for a version *prior* to 6.2.6 (e.g. 6.2.5).

#### Disabling a plugin

To disable a plugin, add it to the `DISABLED_PLUGINS` environment variable. For example:

```bash
DISABLED_PLUGINS=CiscoPlugin,SonicWallPlugin
```

### Environment Variables

NachoVPN is configured using environment variables. This makes it easily compatible with containerised deployments.

Global environment variables:

| Variable | Description | Default |
| -------- | ----------- | ------- |
| `SERVER_FQDN` | The fully qualified domain name of the server. | `connect.nachovpn.local` |
| `EXTERNAL_IP` | The external IP address of the server. | `127.0.0.1` |
| `WRITE_PCAP` | Whether to write captured PCAP files to disk. | `false` |
| `DISABLED_PLUGINS` | A comma-separated list of plugins to disable. | |
| `USE_DYNAMIC_SERVER_THUMBPRINT` | Whether to calculate the server certificate thumbprint dynamically from the server (useful if behind a proxy). | `false` |
| `SERVER_SHA1_THUMBPRINT` | Allows overriding the calculated SHA1 thumbprint for the server certificate. | |
| `SERVER_MD5_THUMBPRINT` | Allows overriding the calculated MD5 thumbprint for the server certificate. | |
| `SMB_ENABLED` | Enables the SMB share, available via the tunnel at `\\10.10.0.1\<SMB_SHARE_NAME>` | `false` |
| `SMB_SHARE_NAME` | The name to use for the SMB share | `SHARE` |
| `SMB_SHARE_PATH` | The path to the directory to use for the SMB share | `smb` |
| `TUNNEL_PRIVATE` | When set to `true`, enables tunneling but disables internet forwarding for VPN clients. Clients can only access the SMB share. | `false` |
| `TUNNEL_FULL` | When set to `true`, enables full tunneling and allows VPN clients to access the internet. Also implies `TUNNEL_PRIVATE=true`. | `false` |

Plugin specific environment variables:

| Variable | Description | Default |
| -------- | ----------- | ------- |
| `VPN_NAME` | The name of the VPN profile, which is presented to the client for Cisco AnyConnect. | `NachoVPN` |
| `PULSE_LOGON_SCRIPT` | The path to the Pulse Secure logon script. | `C:\Windows\System32\calc.exe` |
| `PULSE_LOGON_SCRIPT_MACOS` | The path to the Pulse Secure logon script for macOS. | |
| `PULSE_DNS_SUFFIX` | The DNS suffix to be used for Pulse Secure connections. | `nachovpn.local` |
| `PULSE_USERNAME` | The username to be pre-filled in the Pulse Secure logon dialog. | |
| `PULSE_SAVE_CONNECTION` | Whether to save the Pulse Secure connection in the user's client. | `false` |
| `PULSE_ANONYMOUS_AUTH` | Whether to use anonymous authentication for Pulse Secure connections. If set to `true`, the user will not be prompted for a username or password. | `false` |
| `PULSE_HOST_CHECKER_RULES_FILE` | A JSON file containing a list of registry-based host-checker rules for ICS. See example in `src/nachovpn/plugins/pulse/test/example_rules.json` | |
| `PALO_ALTO_MSI_ADD_FILE` | The path to a file to be added to the Palo Alto installer MSI. | |
| `PALO_ALTO_MSI_COMMAND` | The command to be executed by the Palo Alto installer MSI. | `net user pwnd Passw0rd123! /add && net localgroup administrators pwnd /add` |
| `PALO_ALTO_FORCE_PATCH` | Whether to force the patching of the MSI installer if it already exists in the payloads directory. | `false` |
| `PALO_ALTO_PKG_COMMAND` | The command to be executed by the Palo Alto installer PKG on macOS. | `touch /tmp/pwnd` |
| `CISCO_COMMAND_WIN` | The command to be executed by the Cisco AnyConnect OnConnect.vbs script on Windows. | `calc.exe` |
| `CISCO_COMMAND_MACOS` | The command to be executed by the Cisco AnyConnect OnConnect.sh script on macOS. | `touch /tmp/pwnd` |

## Mitigations

We recommend the following mitigations:

* Ensure SSL-VPN clients are updated to the latest version available from the vendor.
* Most VPN clients support the concept of locking down the VPN profile to a specific endpoint, or using an always-on VPN mode. This should be enabled where possible.
* Unfortunately, in some cases this lockdown can be removed by a malicious local user, therefore it is also recommended to use host-based firewall rules to restrict the IP addresses that the VPN client can communicate with.
* Consider using an Application Control policy, such as WDAC, or an EDR solution to ensure that only approved executables and scripts can be executed by the VPN client.
* Detect and alert on VPN clients executing non-standard child processes.

## References

* [AmberWolf Blog: NachoVPN](https://blog.amberwolf.com/blog/2024/november/introducing-nachovpn---one-vpn-server-to-pwn-them-all/)
* [HackFest Hollywood 2024: Very Pwnable Networks: Exploiting the Top Corporate VPN Clients for Remote Root and SYSTEM Shells, Rich Warren & David Cash](https://github.com/AmberWolfCyber/presentations/blob/main/2024/Very%20Pwnable%20Networks%20-%20HackFest%20Hollywood%202024.pdf) [[video](https://www.youtube.com/watch?v=-MZfkmcZRVg)]
* [BlackHat 2008: Leveraging the Edge: Abusing SSL VPNs, Mike Zusman](https://www.blackhat.com/presentations/bh-usa-08/Zusman/BH_US_08_Zusman_SSL_VPN_Abuse.pdf)
* [BlackHat 2019: Infiltrating Corporate Intranet Like NSA, Orange Tsai & Meh Chang](https://i.blackhat.com/USA-19/Wednesday/us-19-Tsai-Infiltrating-Corporate-Intranet-Like-NSA.pdf)
* [NCC Group: Making New Connections: Leveraging Cisco AnyConnect Client to Drop and Run Payloads, David Cash & Julian Storr](https://www.nccgroup.com/uk/research-blog/making-new-connections-leveraging-cisco-anyconnect-client-to-drop-and-run-payloads/)
* [The OpenConnect Project](https://www.infradead.org/openconnect/)

## Contributing

We welcome contributions! Please open an issue or raise a Pull Request.

If you're interested in developing a new plugin, you can take a look at the [ExamplePlugin](src/nachovpn/plugins/example/plugin.py) to get started.

## License

NachoVPN is licensed under the MIT license. See the [LICENSE](LICENSE) file for details.
