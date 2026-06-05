#!/usr/bin/env python3

import psutil
import ipaddress
import socket
import subprocess
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Scapy is only needed for ARP
try:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ---------------- INTERFACE DISCOVERY ---------------- #

def get_interfaces():
    interfaces = []

    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
                netmask = addr.netmask

                if ip.startswith("127."):
                    continue

                interfaces.append({
                    "name": iface,
                    "ip": ip,
                    "netmask": netmask
                })

    return interfaces


def select_interface(interfaces):
    print("\nAvailable Interfaces:\n")
    for i, iface in enumerate(interfaces, 1):
        cidr = ipaddress.IPv4Network(f"{iface['ip']}/{iface['netmask']}", strict=False)
        print(f"[{i}] {iface['name']:<8} {iface['ip']}/{cidr.prefixlen}")

    while True:
        choice = input("\nSelect interface > ")
        if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
            return interfaces[int(choice) - 1]


# ---------------- NETWORK UTILS ---------------- #

def get_network(interface):
    return ipaddress.IPv4Network(
        f"{interface['ip']}/{interface['netmask']}", strict=False
    )


def detect_gateway():
    gateways = psutil.net_if_stats()
    gws = psutil.net_if_addrs()

    try:
        route = subprocess.check_output("ip route | grep default", shell=True).decode()
        return route.split()[2]
    except:
        return "Unknown"


# ---------------- OS GUESSING ---------------- #

def guess_os(ttl):
    if ttl >= 128:
        return "Windows"
    elif ttl >= 64:
        return "Linux/Unix"
    elif ttl >= 255:
        return "Network Device"
    return "Unknown"


# ---------------- SCANNING METHODS ---------------- #

def icmp_ping(ip):
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            stdout=subprocess.DEVNULL
        )
        if proc.returncode == 0:
            ttl = subprocess.check_output(
                ["ping", "-c", "1", str(ip)]
            ).decode().split("ttl=")[1].split()[0]
            return True, guess_os(int(ttl))
    except:
        pass
    return False, None


def tcp_probe(ip, ports=[22, 80, 443]):
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            if s.connect_ex((str(ip), port)) == 0:
                s.close()
                return True, "TCP Response"
            s.close()
        except:
            pass
    return False, None


def arp_scan(network):
    if not SCAPY_AVAILABLE:
        print("[!] Scapy not installed")
        sys.exit(1)

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    result = srp(pkt, timeout=2)[0]

    hosts = []
    for _, recv in result:
        hosts.append({
            "ip": recv.psrc,
            "mac": recv.hwsrc,
            "os": "Unknown"
        })
    return hosts


# ---------------- MAIN SCANNER ---------------- #

def scan_network(network, method):
    live_hosts = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {}

        for ip in network.hosts():
            if method == "icmp":
                futures[executor.submit(icmp_ping, ip)] = ip
            elif method == "tcp":
                futures[executor.submit(tcp_probe, ip)] = ip

        for future in as_completed(futures):
            ip = futures[future]
            alive, os_guess = future.result()
            if alive:
                live_hosts.append({
                    "ip": str(ip),
                    "mac": "N/A",
                    "os": os_guess or "Unknown"
                })

    return live_hosts


# ---------------- USER MENU ---------------- #

def select_scan_method():
    print("\nHost Discovery Method:\n")
    print("[1] ICMP Ping")
    print("[2] ARP Scan (LAN only)")
    print("[3] TCP Probe")

    while True:
        c = input("\nSelect method > ")
        if c == "1":
            return "icmp"
        elif c == "2":
            return "arp"
        elif c == "3":
            return "tcp"


# ---------------- MAIN ---------------- #

def main():
    if os.geteuid() != 0:
        print("[!] Run as root for full functionality\n")

    interfaces = get_interfaces()
    if not interfaces:
        print("[!] No valid interfaces found")
        sys.exit(1)

    iface = select_interface(interfaces)
    network = get_network(iface)

    print(f"\n[*] Selected Interface : {iface['name']}")
    print(f"[*] Network           : {network}")
    print(f"[*] Gateway           : {detect_gateway()}")

    method = select_scan_method()

    print("\n[*] Scanning...\n")

    if method == "arp":
        hosts = arp_scan(network)
    else:
        hosts = scan_network(network, method)

    print("\n--- LIVE HOSTS ---\n")
    for h in hosts:
        print(f"{h['ip']:<15} {h['mac']:<18} {h['os']}")

    print(f"\n[+] Scan complete. Hosts found: {len(hosts)}\n")


if __name__ == "__main__":
    main()

