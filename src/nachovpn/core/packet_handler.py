from pyroute2 import AsyncIPRoute
from dataclasses import dataclass, field
from nachovpn.core.ip_manager import IPPool
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter

import nftables
import asyncio
import os
import logging
import ipaddress
import socket
import time
import uuid
import struct
import fcntl
import threading

TUNNEL_MTU = int(os.getenv("TUNNEL_MTU", 1400))
LEASE_SECS = int(os.getenv("LEASE_SECS", 5 * 60))                       # 5 minutes
LEASE_CLEANUP_INTERVAL = int(os.getenv("LEASE_CLEANUP_INTERVAL", 60))   # 1 minute
VPN_SUBNET = "10.10.0.0/16"

# Tunnel forwarding control
TUNNEL_PRIVATE = os.getenv("TUNNEL_PRIVATE", "false").lower() == "true"
TUNNEL_FULL = os.getenv("TUNNEL_FULL", "false").lower() == "true"
TUNNEL_ENABLED = (TUNNEL_PRIVATE or TUNNEL_FULL) and os.name != 'nt'

IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454CA
IFF_TUN   = 0x0001

@dataclass
class ClientInfo:
    """Information about a connected client"""
    sock: socket.socket
    ip_address: str
    connection_id: str
    callback: callable
    last_seen: float = field(default_factory=time.time)

class PacketHandler:
    """
    TUN-based packet handler using nftables
    """
    def __init__(self, write_pcap=False, pcap_filename=None):
        """Initialize packet handler"""
        self.logger = logging.getLogger(__name__)
        self.write_pcap = write_pcap
        self.pcap_filename = pcap_filename
        self._pcap_writer = None

        self.logger.debug(f"[TUN] PacketHandler instantiated in thread {threading.current_thread().name}")

        # Initialize pyroute2 and nftables
        self._ipr = AsyncIPRoute()
        self.nft = nftables.Nftables()

        # TUN interface name
        self.tun_name = "nacho0"

        # Client management
        self.clients = {}                   # ip_address -> ClientInfo
        self.conn_to_ip = {}                # connection_id -> ip_address
        self.ip_pool = IPPool(VPN_SUBNET)
        self.client_lock = asyncio.Lock()
        self.connection_states = {}         # connection_id -> bool (True if connection is alive)

        # Packet queuing
        self.packet_queues = {}             # connection_id -> asyncio.Queue
        self.send_tasks = {}                # connection_id -> asyncio.Task

        # Cache TUN file descriptor
        self.tun_fd = None

        # Background tasks
        self._lease_cleanup_task = None
        self._closed = False

    def _setup_nftables(self):
        """Configure nftables rules"""
        try:
            # First try to flush and delete existing table
            try:
                self.nft.cmd('flush table inet vpn')
                self.nft.cmd('delete table inet vpn')
                self.logger.info("Flushed existing nftables rules")
            except Exception as e:
                self.logger.warning(f"Error flushing existing rules: {e}")

            # MSS clamp to TUNNEL_MTU
            tcp_mss = TUNNEL_MTU

            # Get the gateway IP (first host in the subnet)
            subnet = ipaddress.ip_network(VPN_SUBNET)
            gateway_ip = str(next(subnet.hosts()))

            # Get addr / len from VPN_SUBNET
            vpn_addr, vpn_len = VPN_SUBNET.split("/")

            # Log the tunnel forwarding configuration
            self.logger.info(f"Tunnel forwarding configuration: TUNNEL_PRIVATE={TUNNEL_PRIVATE}, TUNNEL_FULL={TUNNEL_FULL}")

            # Build nftables rules
            rules = [
                {
                    "add": {
                        "table": {
                            "family": "inet",
                            "name": "vpn"
                        }
                    }
                },
                {
                    "add": {
                        "chain": {
                            "family": "inet",
                            "table": "vpn",
                            "name": "input",
                            "type": "filter",
                            "hook": "input",
                            "prio": 0,
                            "policy": "accept"
                        }
                    }
                },
                {
                    "add": {
                        "chain": {
                            "family": "inet",
                            "table": "vpn",
                            "name": "forward",
                            "type": "filter",
                            "hook": "forward",
                            "prio": 0,
                            "policy": "drop"
                        }
                    }
                },
                {
                    "add": {
                        "chain": {
                            "family": "inet",
                            "table": "vpn",
                            "name": "postroute",
                            "type": "nat",
                            "hook": "postrouting",
                            "prio": 100
                        }
                    }
                },
                {
                    "add": {
                        "chain": {
                            "family": "inet",
                            "table": "vpn",
                            "name": "preroute",
                            "type": "nat",
                            "hook": "prerouting",
                            "prio": -100
                        }
                    }
                },
                # Allow TCP 445 to gateway IP from VPN subnet
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": "vpn",
                            "chain": "input",
                            "expr": [
                                {"match": {"left": {"meta": {"key": "iifname"}}, "op": "==", "right": self.tun_name}},
                                {"match": {"left": {"payload": {"protocol": "ip", "field": "saddr"}}, "op": "in", "right": {"prefix": {"addr": vpn_addr, "len": int(vpn_len)}}}},
                                {"match": {"left": {"payload": {"protocol": "ip", "field": "daddr"}}, "op": "==", "right": gateway_ip}},
                                {"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "op": "==", "right": 445}},
                                {"accept": None}
                            ]
                        }
                    }
                },
                # Default drop for all other VPN interface traffic
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": "vpn",
                            "chain": "input",
                            "expr": [
                                {"match": {"left": {"meta": {"key": "iifname"}}, "op": "==", "right": self.tun_name}},
                                {"drop": None}
                            ]
                        }
                    }
                },
                # Accept established/related
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": "vpn",
                            "chain": "forward",
                            "expr": [
                                {"match": {"left": {"ct": {"key": "state"}}, "op": "in", "right": {"set": ["established", "related"]}}},
                                {"accept": None}
                            ]
                        }
                    }
                },
                # Drop traffic to the gateway IP
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": "vpn",
                            "chain": "forward",
                            "expr": [
                                {"match": {"left": {"payload": {"protocol": "ip", "field": "daddr"}}, "op": "==", "right": gateway_ip}},
                                {"drop": None}
                            ]
                        }
                    }
                }
            ]

            # Add forwarding rules if TUNNEL_FULL is enabled
            if TUNNEL_FULL:
                self.logger.info("Adding internet forwarding rules - VPN clients can access the internet")
                # Drop traffic to private/LAN ranges
                rules.append({
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": "vpn",
                            "chain": "forward",
                            "expr": [
                                {"match": {"left": {"payload": {"protocol": "ip", "field": "daddr"}}, "op": "in", "right": {"set": [
                                    {"prefix": {"addr": "10.0.0.0", "len": 8}},
                                    {"prefix": {"addr": "127.0.0.0", "len": 8}},
                                    {"prefix": {"addr": "169.254.169.254", "len": 32}},
                                    {"prefix": {"addr": "172.16.0.0", "len": 12}},
                                    {"prefix": {"addr": "192.168.0.0", "len": 16}}
                                ]}}},
                                {"drop": None}
                            ]
                        }
                    }
                })
                # Drop broadcast and multicast traffic
                rules.append({
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": "vpn",
                            "chain": "forward",
                            "expr": [
                                {"match": {"left": {"payload": {"protocol": "ip", "field": "daddr"}}, "op": "in", "right": {"set": [
                                    {"prefix": {"addr": "224.0.0.0", "len": 4}},
                                    {"prefix": {"addr": "255.255.255.255", "len": 32}}
                                ]}}},
                                {"drop": None}
                            ]
                        }
                    }
                })
                # Accept all other VPN client traffic to the internet
                rules.append({
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": "vpn",
                            "chain": "forward",
                            "expr": [
                                {"match": {"left": {"meta": {"key": "iifname"}}, "op": "==", "right": self.tun_name}},
                                {"accept": None}
                            ]
                        }
                    }
                })
                # Masquerade traffic from VPN subnet
                rules.append({
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": "vpn",
                            "chain": "postroute",
                            "expr": [
                                {"match": {"left": {"payload": {"protocol": "ip", "field": "saddr"}}, "op": "in", "right": {"prefix": {"addr": vpn_addr, "len": int(vpn_len)}}}},
                                {"match": {"left": {"meta": {"key": "oifname"}}, "op": "!=", "right": self.tun_name}},
                                {"masquerade": None}
                            ]
                        }
                    }
                })
            else:
                self.logger.info("Internet forwarding disabled - VPN clients can only access SMB share")

            cmd = {"nftables": rules}

            # Apply nftables rules
            rc, _, err = self.nft.json_cmd(cmd)
            if rc:
                raise RuntimeError(f"Failed to apply nftables rules: {err}")

            self.logger.info("Configured nftables rules")

            # Check if IP forwarding is enabled
            try:
                with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                    ip_forward = f.read().strip()
                if ip_forward != '1':
                    self.logger.error(f"IP forwarding is not enabled. Please enable it with: sudo sysctl -w net.ipv4.ip_forward=1")
                self.logger.info("IP forwarding is enabled")
            except FileNotFoundError:
                self.logger.error("Cannot read IP forwarding status from /proc/sys/net/ipv4/ip_forward. Please ensure IP forwarding is enabled with: sudo sysctl -w net.ipv4.ip_forward=1")

            # Add MSS clamping rules
            try:
                self.nft.cmd(f'add rule inet vpn forward iifname {self.tun_name} ip saddr 10.10.0.0/16 tcp flags syn tcp option maxseg size set {tcp_mss}')
                self.nft.cmd(f'add rule inet vpn forward oifname {self.tun_name} ip daddr 10.10.0.0/16 tcp flags syn tcp option maxseg size set {tcp_mss}')
                self.logger.info(f"Added TCP MSS clamping rules with MSS {tcp_mss}")
            except Exception as e:
                self.logger.error(f"Failed to add TCP MSS clamping rules: {e}")
                raise

            # Verify rules were applied
            try:
                result = self.nft.cmd('list ruleset')
                self.logger.debug(f"Current nftables rules: {result}")
            except Exception as e:
                self.logger.error(f"Failed to list rules: {e}")

        except Exception as e:
            self.logger.error(f"Failed to configure nftables: {e}")
            raise

    async def _setup_tun_interface(self):
        """Create and configure the TUN interface"""
        try:
            idx = await self._ipr.link_lookup(ifname=self.tun_name)
            if idx:
                self.logger.info("Removing existing interface %s", self.tun_name)
                await self._ipr.link("del", index=idx[0])

            # Create TUN interface
            await self._ipr.link(
                "add",
                ifname=self.tun_name,
                kind="tuntap",
                mode="tun",
                iflags=IFF_TUN | IFF_NO_PI
            )

            # Get interface info
            idx = (await self._ipr.link_lookup(ifname=self.tun_name))[0]
            info = await self._ipr.link("get", index=idx)
            self.logger.debug(f"[TUN] Interface created with flags: {info[0]['flags']}")

            # Set MTU
            await self._ipr.link("set", index=idx, mtu=TUNNEL_MTU, state="up")
            self.logger.info(f"[TUN] Set interface MTU to {TUNNEL_MTU} bytes")

            subnet = ipaddress.ip_network(VPN_SUBNET)
            gateway_ip = str(next(subnet.hosts()))
            await self._ipr.addr("add", index=idx, address=gateway_ip,
                        prefixlen=subnet.prefixlen)

            self.logger.info("Created %s %s/%s",
                            self.tun_name, gateway_ip, subnet.prefixlen)

            # Disable IPv6 on the nacho0 interface
            ipv6_disable_path = f"/proc/sys/net/ipv6/conf/{self.tun_name}/disable_ipv6"
            if os.path.exists(ipv6_disable_path):
                try:
                    with open(ipv6_disable_path, "w") as f:
                        f.write("1\n")
                    self.logger.info(f"Disabled IPv6 on {self.tun_name}")
                except Exception as e:
                    self.logger.warning(f"Failed to disable IPv6 on {self.tun_name}: {e}")

        except Exception:
            self.logger.exception("Failed to create TUN interface")
            raise

    def _setup_tun_fd(self) -> None:
        """Open /dev/net/tun and bind it to the nacho0 interface."""
        try:
            # Open the TUN character device
            fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
            self.logger.debug(f"[TUN] Opened /dev/net/tun with fd={fd}")

            # Tell the kernel which interface this fd belongs to
            ifr = struct.pack(
                "16sH",
                self.tun_name.encode(),
                IFF_TUN | IFF_NO_PI
            )
            self.logger.debug(f"[TUN] Setting interface flags: IFF_TUN={IFF_TUN}, IFF_NO_PI={IFF_NO_PI}")
            fcntl.ioctl(fd, TUNSETIFF, ifr)
            self.logger.debug(f"[TUN] Bound fd={fd} to interface {self.tun_name}")

            # Store and register with the event loop
            self.tun_fd = fd
            self._loop.add_reader(fd, self._on_tun_ready)
            self.logger.debug(f"[TUN] Registered fd={fd} with event loop")

        except Exception as e:
            self.logger.error(f"[TUN] Failed to open TUN file descriptor: {e}")
            raise

    def _on_tun_ready(self):
        """Synchronous callback when TUN fd is ready for reading"""
        try:
            self.logger.debug("[TUN] _on_tun_ready called")

            # Read packet from TUN interface
            packet_data = os.read(self.tun_fd, 65535)
            if not packet_data:
                self.logger.debug("[TUN] No data available")
                return

            self.logger.debug(f"[TUN] Raw packet data: {packet_data.hex()}")

            # Get IP version
            version = packet_data[0] >> 4
            if version != 4:
                self.logger.debug(f"[TUN] Ignoring non-IPv4 packet: version={version}, first_bytes={packet_data[:4].hex()}")
                return

            # IPv4 packet
            if len(packet_data) >= 20:
                dest_ip = socket.inet_ntoa(packet_data[16:20])
                src_ip = socket.inet_ntoa(packet_data[12:16])
                self.logger.debug(f"[TUN] IPv4 packet: src={src_ip} dst={dest_ip} len={len(packet_data)}")
                if dest_ip:
                    self.logger.debug(f"[TUN] Handling reply packet for dest_ip={dest_ip}, src_ip={src_ip}, len={len(packet_data)}")
                    self._loop.create_task(self._handle_reply_packet(packet_data, dest_ip))
            else:
                self.logger.warning(f"[TUN] Packet too short for IPv4: len={len(packet_data)}")
        except BlockingIOError:
            # No data available
            pass
        except Exception as e:
            self.logger.error(f"[TUN] Error reading from TUN interface: {e}")

    async def _lease_cleanup(self):
        """Periodically check for and reclaim expired client leases"""
        while True:
            await asyncio.sleep(LEASE_CLEANUP_INTERVAL)
            try:
                async with self.client_lock:
                    now = time.time()
                    # Find stale clients
                    stale = [
                        ip for ip, client in self.clients.items()
                        if now - client.last_seen > LEASE_SECS
                    ]
                    # Reclaim them
                    for ip in stale:
                        await self._reclaim_client(ip)
            except Exception as e:
                self.logger.error(f"Error in lease cleanup: {e}")

    async def _reclaim_client(self, ip_address):
        """Reclaim a client's resources"""
        try:
            client = self.clients.pop(ip_address, None)
            if client:
                # Remove connection mapping
                self.conn_to_ip.pop(client.connection_id, None)

                # Close the socket
                try:
                    if hasattr(client, 'sock'):
                        client.sock.close()
                except Exception:
                    pass

                # Release the IP
                self.ip_pool.release(ip_address)
                self.logger.info(f"Reclaimed idle client {client.connection_id} with IP {ip_address}")
        except Exception as e:
            self.logger.error(f"Error reclaiming client {ip_address}: {e}")

    def _send_all_blocking(self, sock, data):
        """Send all bytes on a blocking socket."""
        try:
            sock.setblocking(True)
            sock.sendall(data)
            return True
        except Exception as e:
            self.logger.error(f"Error sending data (blocking): {e}")
            return False

    async def _send_packets(self, connection_id, queue):
        """Background task to send packets from queue to client"""
        try:
            while True:
                # Get next packet from queue
                packet_data = await queue.get()
                if packet_data is None:  # Shutdown signal
                    break

                # Get client info
                ip_address = self.conn_to_ip.get(connection_id)
                if not ip_address:
                    self.logger.warning(f"[TUN] No IP address found for connection_id {connection_id} in _send_packets")
                    continue

                client = self.clients.get(ip_address)
                if not client:
                    self.logger.warning(f"[TUN] No client found for IP {ip_address} in _send_packets")
                    continue

                # Check if connection is still alive
                if not self.connection_states.get(connection_id, False):
                    self.logger.warning(f"[TUN] Connection {connection_id} is no longer alive in _send_packets")
                    continue

                self.logger.debug(f"[TUN] Sending reply packet of size {len(packet_data)} bytes to client {connection_id} (IP {ip_address})")

                try:
                    await self._loop.run_in_executor(
                        None, 
                        self._send_all_blocking,
                        client.sock,
                        packet_data
                    )
                except Exception as e:
                    self.logger.error(f"[TUN] Failed to send data to client {connection_id}: {e}")
                    self.connection_states[connection_id] = False
                    self.destroy_session(connection_id)
                    break

                # Update client state under lock
                async with self.client_lock:
                    if ip_address in self.clients:
                        self.clients[ip_address].last_seen = time.time()
                        # Touch the IP to keep lease alive
                        self.ip_pool.touch(ip_address)
                        self.logger.debug(f"[TUN] Updated client {connection_id} last_seen time")

                # Mark task as done
                queue.task_done()

        except Exception as e:
            self.logger.error(f"[TUN] Error in send_packets task for {connection_id}: {e}")
            self.connection_states[connection_id] = False
            self.destroy_session(connection_id)

    def register_client(self, connection_id, sock, wrapper_callback):
        """Register a new client and assign an IP"""
        try:
            # Allocate IP from pool
            ip_address = self.ip_pool.alloc()

            # Store client info
            self.clients[ip_address] = ClientInfo(
                sock=sock,
                ip_address=ip_address,
                connection_id=connection_id,
                callback=wrapper_callback,
                last_seen=time.time()
            )

            # Add connection mapping
            self.conn_to_ip[connection_id] = ip_address

            # Mark connection as alive
            self.connection_states[connection_id] = True

            # Create packet queue and start send task
            self.packet_queues[connection_id] = asyncio.Queue(maxsize=100)
            self.send_tasks[connection_id] = self._loop.create_task(
                self._send_packets(connection_id, self.packet_queues[connection_id])
            )

            self.logger.info(f"Registered client {connection_id} with IP {ip_address}")
            return ip_address
        except Exception as e:
            self.logger.error(f"Failed to register client {connection_id}: {e}")
            raise

    def destroy_session(self, connection_id):
        """Unregister a client and release their IP"""
        ip_address = self.conn_to_ip.get(connection_id)
        if ip_address and ip_address in self.clients:
            # Remove connection mapping
            self.conn_to_ip.pop(connection_id, None)

            # Remove client info
            del self.clients[ip_address]

            # Remove connection state
            self.connection_states.pop(connection_id, None)

            # Clean up packet queue and send task
            queue = self.packet_queues.pop(connection_id, None)
            if queue:
                # Signal task to stop
                self._loop.call_soon_threadsafe(queue.put_nowait, None)

            task = self.send_tasks.pop(connection_id, None)
            if task:
                task.cancel()

            # Release the IP
            self.ip_pool.release(ip_address)
            self.logger.info(f"Unregistered client {connection_id}")

    async def _handle_reply_packet(self, packet_data, dest_ip):
        """Handle a reply packet from the TUN interface"""
        try:
            # Lookup client by IP
            client = self.clients.get(dest_ip)
            self.logger.debug(f"[TUN] Handling reply packet for dest_ip={dest_ip}, client={client}")
            if client:
                # Check if connection is still alive
                if not self.connection_states.get(client.connection_id, False):
                    self.logger.warning(f"[TUN] Connection {client.connection_id} is no longer alive, skipping packet")
                    return

                # Use the plugin's wrapper_callback
                if client.callback:
                    self.logger.debug(f"[TUN] Using callback for client {client.connection_id}")
                    wrapped_data = client.callback(packet_data, client)
                else:
                    self.logger.debug(f"[TUN] No callback for client {client.connection_id}, using raw data")
                    wrapped_data = packet_data

                # Add packet to queue
                self.logger.debug(f"[TUN] Queuing reply packet to client {client.connection_id} (IP {dest_ip}): original size={len(packet_data)}, wrapped size={len(wrapped_data)}")
                queue = self.packet_queues.get(client.connection_id)
                if queue:
                    try:
                        queue.put_nowait(wrapped_data)
                        self.logger.debug(f"[TUN] Queued reply packet to client {client.connection_id}")
                    except asyncio.QueueFull:
                        self.logger.warning(f"[TUN] Client {client.connection_id} queue full, dropping packet")
                else:
                    self.logger.warning(f"[TUN] No queue found for client {client.connection_id}")
            else:
                self.logger.warning(f"[TUN] No client found for destination IP {dest_ip}")
        except Exception as e:
            self.logger.error(f"[TUN] Error handling reply packet: {e}")

    def handle_client_packet(self, packet_data, connection_id):
        """Handle a packet from a client"""
        try:
            self.logger.debug(f"Handling client packet for connection_id {connection_id}")
            
            ip_address = self.conn_to_ip.get(connection_id)
            if not ip_address:
                self.logger.error(f"No client found for connection_id {connection_id}")
                return
            
            client_info = self.clients.get(ip_address)
            if not client_info:
                self.logger.error(f"No ClientInfo found for IP {ip_address}")
                return

            src_ip = socket.inet_ntoa(packet_data[12:16]) if len(packet_data) >= 16 and (packet_data[0] >> 4) == 4 else None
            dst_ip = socket.inet_ntoa(packet_data[16:20]) if len(packet_data) >= 20 and (packet_data[0] >> 4) == 4 else None
            self.logger.debug(f"[Client] Packet: src={src_ip} dst={dst_ip} len={len(packet_data)}")

            # Update last seen time
            async def update_client():
                async with self.client_lock:
                    if ip_address in self.clients:
                        self.clients[ip_address].last_seen = time.time()
            self._loop.create_task(update_client())

            if TUNNEL_ENABLED:
                # Write packet to TUN interface
                if self.tun_fd is not None:
                    try:
                        bytes_written = os.write(self.tun_fd, packet_data)
                        self.logger.debug(f"[TUN] Wrote {bytes_written} bytes to TUN interface")
                    except BlockingIOError:
                        # TUN queue is full, drop the packet
                        self.logger.warning("TUN queue full, dropping packet")
                    except Exception as e:
                        self.logger.error(f"Error writing to TUN interface: {e}")
                        self.logger.error("Stack trace:", exc_info=True)
                else:
                    self.logger.error("TUN file descriptor not available")
            else:
                self.logger.debug(f"[TUN] Tunnel disabled. Received packet from {src_ip} to {dst_ip}")
                self.append_to_pcap(packet_data)

        except Exception as e:
            self.logger.error(f"Error handling client packet: {e}")

    def append_to_pcap(self, packet):
        """Append packet to PCAP file if enabled"""
        try:
            if self.write_pcap and self._pcap_writer is not None:
                pkt = self._fake_eth / Raw(load=bytes(packet))
                self._pcap_writer.write(pkt)
        except Exception as e:
            self.logger.error(f'Error appending to PCAP: {e}')

    async def close(self):
        """Clean up resources"""
        if self._closed:
            return

        try:
            # Cancel background tasks
            if TUNNEL_ENABLED and hasattr(self, '_lease_cleanup_task'):
                self._lease_cleanup_task.cancel()
                try:
                    await self._lease_cleanup_task
                except asyncio.CancelledError:
                    pass

            # Close all client connections
            async with self.client_lock:
                for client in list(self.clients.values()):
                    try:
                        if hasattr(client, 'sock'):
                            client.sock.close()
                    except Exception:
                        pass
                self.clients.clear()
                self.conn_to_ip.clear()

            # Clean up tunneling resources
            if TUNNEL_ENABLED:
                # Remove TUN fd from event loop
                if self.tun_fd is not None:
                    try:
                        self._loop.remove_reader(self.tun_fd)
                        self.logger.info("Removed TUN fd from event loop")
                    except Exception as e:
                        self.logger.error(f"Error removing TUN fd from event loop: {e}")

                # Close TUN file descriptor
                if self.tun_fd is not None:
                    try:
                        os.close(self.tun_fd)
                        self.logger.info("Closed TUN file descriptor")
                    except Exception as e:
                        self.logger.error(f"Error closing TUN file descriptor: {e}")

                try:
                    self.nft.cmd('flush table inet vpn')
                    self.nft.cmd('delete table inet vpn')
                    self.logger.info("Cleaned up nftables rules")
                except Exception as e:
                    self.logger.error(f"Error cleaning up nftables: {e}")

                # Close IPRoute
                if hasattr(self, '_ipr'):
                    try:
                        await self._ipr.close()
                        self.logger.info("Closed IPRoute")
                    except Exception as e:
                        self.logger.error(f"Error closing IPRoute: {e}")

            # Close PCAP writer
            if self._pcap_writer is not None:
                try:
                    self._pcap_writer.close()
                    self.logger.info("Closed PCAP writer")
                except Exception as e:
                    self.logger.error(f"Error closing PCAP writer: {e}")

            self._closed = True
            self.logger.info("PacketHandler closed successfully")

        except Exception as e:
            self.logger.error(f"Error in cleanup: {e}")
            raise

    def create_session(self, sock, wrapper_callback):
        """Create a new session: generate connection_id, assign IP, and register client."""
        connection_id = str(uuid.uuid4())
        ip_address = self.register_client(connection_id, sock, wrapper_callback)
        return connection_id, ip_address

    def get_assigned_ip(self, connection_id):
        """Return the assigned IP for a given connection_id, or None if not found."""
        return self.conn_to_ip.get(connection_id)

    def assign_socket(self, connection_id, sock):
        """Assign or update the socket for an existing client session."""
        ip_address = self.conn_to_ip.get(connection_id)
        if ip_address and ip_address in self.clients:
            self.logger.info(f"Assigning new socket to connection_id {connection_id} (IP {ip_address})")
            self.clients[ip_address].sock = sock
            return True
        self.logger.warning(f"assign_socket: No client found for connection_id {connection_id}")
        return False

    async def start(self):
        """Start the packet handler's background tasks"""
        try:
            # Set the event loop for this thread
            self._loop = asyncio.get_running_loop()
            self.logger.info(f"[TUN] PacketHandler using event loop {self._loop} in thread {threading.current_thread().name}")

            # Log the tunnel configuration
            self.logger.info(f"Tunnel configuration: TUNNEL_PRIVATE={TUNNEL_PRIVATE}, TUNNEL_FULL={TUNNEL_FULL}")

            if TUNNEL_ENABLED:
                # Initialize nftables
                self._setup_nftables()

                # Set up TUN interface
                await self._setup_tun_interface()

                # Set up TUN file descriptor
                self._setup_tun_fd()

                # Start background tasks
                if self._lease_cleanup_task is None:
                    self._lease_cleanup_task = asyncio.create_task(self._lease_cleanup())
                    self.logger.info("Started lease cleanup task")
            else:
                self.logger.info("Tunnel disabled - skipping nftables, TUN interface, and lease cleanup setup")

            # Set up PCAP writer (always enabled if configured)
            if self.write_pcap and self.pcap_filename:
                os.makedirs(os.path.dirname(self.pcap_filename), exist_ok=True)
                self._fake_eth = Ether(src='01:02:03:04:05:06', dst='ff:ff:ff:ff:ff:ff')
                self.logger.info(f"Using TUN interface MAC {self._fake_eth.src} for PCAP")

                # Open PCAP writer
                self._pcap_writer = PcapWriter(self.pcap_filename, append=True)
                self.logger.info(f"Opened PCAP writer for {self.pcap_filename}")
        except Exception as e:
            self.logger.error(f"Error starting packet handler: {e}")
            raise
