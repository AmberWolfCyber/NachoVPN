from __future__ import annotations
import ipaddress, itertools, threading, time, os

LEASE_SECS = int(os.getenv("LEASE_SECS", 5 * 60))
VPN_SUBNET = "10.10.0.0/16"

class IPPool:
    """Round-robin allocator with lease/idle-timeout."""
    def __init__(self, cidr: str = VPN_SUBNET):
        self.net  = ipaddress.ip_network(cidr)
        self.host_iter = itertools.cycle(self.net.hosts())
        self.lock = threading.Lock()
        # ip_str -> last_seen_epoch
        self.inuse: dict[str, float] = {}

        # Reserve gateway
        gw = str(next(self.host_iter))
        self.inuse[gw] = float('inf')

    def alloc(self) -> str:
        now = time.time()
        with self.lock:
            for _ in range(self.net.num_addresses - 2):
                cand = str(next(self.host_iter))
                last = self.inuse.get(cand, 0)
                if now - last > LEASE_SECS:
                    self.inuse[cand] = now
                    return cand
            raise RuntimeError("Address pool exhausted")

    def touch(self, ip: str):
        """Call whenever we see traffic from ip to keep the lease alive."""
        with self.lock:
            if ip in self.inuse:
                self.inuse[ip] = time.time()

    def release(self, ip: str):
        with self.lock:
            self.inuse.pop(ip, None)
