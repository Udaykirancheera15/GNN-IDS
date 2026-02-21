#!/usr/bin/env python3
import socket
import random
import time
from scapy.all import IP, TCP, send

def get_local_ip():
    """
    Retrieves the machine's external-facing IP.
    Sending traffic to 127.0.0.1 won't trigger the sniffer bound to wlp2s0, 
    so we must target the actual LAN IP.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
        except Exception:
            return '127.0.0.1'

def simulate_port_scan():
    target_ip = get_local_ip()
    print(f"[*] Target IP resolved to: {target_ip}")
    print("[*] Initiating high-velocity TCP SYN Scan (1,000 packets)...")
    
    start_time = time.time()
    
    # Fire 1000 SYN packets at random high ports
    for i in range(1, 1001):
        target_port = random.randint(1024, 65535)
        source_port = random.randint(1024, 65535)
        
        # Forge a raw IP/TCP packet with the SYN flag ("S") set
        pkt = IP(dst=target_ip) / TCP(sport=source_port, dport=target_port, flags="S")
        
        # Inject into the network stack (verbose=0 suppresses scapy output)
        send(pkt, verbose=0)
        
        if i % 200 == 0:
            print(f"  -> {i} packets injected.")
            
    elapsed = time.time() - start_time
    print(f"[*] Scan complete in {elapsed:.2f} seconds.")
    print("[*] NOTE: The IDS will classify these flows once the 60-second FLOW_TIMEOUT expires.")

if __name__ == "__main__":
    simulate_port_scan()
