import sys
import re
import socket
import scapy.all as sp
import requests
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP

# Function to scan IP addresses in a given CIDR range
def ip_scanner(cidr_range):
    network, netmask = cidr_range.split('/')
    ip_range = [f"{network}.{i}" for i in range(int(netmask) + 1)]

    live_ips = []
    for ip in ip_range:
        response = sp.sr1(IP(dst=ip) / TCP(dport=80), timeout=1, verbose=0)
        if response is not None and response[1] == 1:
            live_ips.append(ip)

    return live_ips

# Function to get reverse IP for a given CIDR range
def cidr_reverse_ip(cidr_range):
    network, _ = cidr_range.split('/')
    return f"Reverse IP for {cidr_range}: {socket.gethostbyaddr(network)}"

# Function to scan open ports on target IP addresses
def tls_scanner(target_ips, port=443):
    open_ports = []
    for ip in target_ips:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append((ip, port))
        sock.close()
    return open_ports

# Function to scan a text file containing IP addresses or domains
def file_scanner(file_path):
    with open(file_path, 'r') as file:
        targets = file.readlines()
    return ip_scanner('\n'.join(targets).strip())

# Function to scan IP addresses or domains for proxies
def proxy_scanner(targets):
    proxy_list = []
    for target in targets:
        try:
            response = requests.get('https://example.com', proxies={'http': f'http://{target}:80'})
            if response.status_code == 200:
                proxy_list.append(target)
        except:
            pass
    return proxy_list

# Function to extract domains from a given text
def domain_extractor(text):
    domain_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    domains = re.findall(domain_pattern, text)
    return domains

# Function to send custom HTTP requests to targets
def custom_port_scanning(targets, port, method='GET', payload=None):
    results = []
    for target in targets:
        try:
            if payload:
                response = requests.request(method, f'http://{target}:{port}', data=payload)
            else:
                response = requests.request(method, f'http://{target}:{port}')
            results.append((target, port, response.status_code))
        except:
            pass
    return results

# Function to generate payload for an HTTP proxy
def payload_maker(proxy_type, user, password):
    if proxy_type == 'ssh':
        return f'ssh://{user}:{password}@proxy_ip:port'
    elif proxy_type == 'http':
        return f'http://{user}:{password}@proxy_ip:port'
    else:
        return "Invalid proxy type. Please choose 'ssh' or 'http'."

if __name__ == '__main__':
    # Usage example
    cidr_range = '192.168.1.0/24'
    targets = ip_scanner(cidr_range)
    print(f"Live IPs: {targets}")

    print(cidr_reverse_ip(cidr_range))

    open_ports = tls_scanner(targets)
    print(f"Open TLS ports: {open_ports}")

    file_targets = file_scanner('targets.txt')
    print(f"Live IPs from file: {file_targets}")

    proxies = proxy_scanner(file_targets)
    print(f"Active proxies: {proxies}")

    domains = domain_extractor('Visit my website at https://example.com or check out https://another-example.com')
    print(f"Extracted domains: {domains}")

    custom_results = custom_port_scanning(proxies, 8080, method='POST', payload='custom_payload')
    print(f"Custom port scan results: {custom_results}")

    ssh_payload = payload_maker('ssh', 'username', 'password')
    print(f"SSH payload: {ssh_payload}")

    http_payload = payload_maker('http', 'username', 'password')
    print(f"HTTP payload: {http_payload}")
