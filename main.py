import json
import random
import requests
import socket
import threading
import time
import ssl
from datetime import datetime

COMMON_PORTS = [21, 22, 23, 25, 80, 443, 8080]
lock = threading.Lock()

def generate_random_ip():
    """Generate a random IP address."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

def get_geolocation(ip):
    """Fetch geolocation data for an IP address."""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=1)
        return response.json()
    except requests.RequestException:
        return {}

def get_dns_info(ip):
    """Fetch DNS information for an IP address."""
    try:
        result = socket.gethostbyaddr(ip)
        return {"hostname": result[0], "aliases": result[1], "ip": result[2]}
    except socket.herror:
        return {}

def get_isp_info(ip):
    """Fetch ISP information for an IP address."""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=1)
        return response.json().get("org", "Unknown ISP")
    except requests.RequestException:
        return "Unknown ISP"

def get_response_headers(ip):
    """Fetch HTTP response headers for an IP address."""
    try:
        response = requests.get(f"http://{ip}", timeout=1)
        return dict(response.headers)
    except requests.RequestException:
        return {}

def get_ssl_certificate(ip):
    """Fetch SSL certificate information for an HTTPS IP."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": dict(cert['issuer']),
                    "expiration": cert['notAfter']
                }
    except Exception:
        return {}

def perform_port_scan(ip, ports):
    """Perform a fast scan on common ports to check if they are open."""
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)  # Timeout for fast scanning
            result = sock.connect_ex((ip, port))
            if result == 0:  # If result is 0, the port is open
                open_ports.append(port)
    return open_ports

def check_ip_with_request(ip):
    """Check if an IP is reachable and handle redirection. Return status code, redirected URL if any, ping time, and timestamp."""
    start_time = time.time()
    ping_time = None
    try:
        response = requests.get(f"http://{ip}", timeout=1, allow_redirects=True)
        ping_time = (time.time() - start_time) * 1000
        if response.history:
            redirect_url = response.url
            return {"code": response.status_code, "redirected_to": redirect_url, "ping_time": ping_time}
        else:
            return {"code": response.status_code, "ping_time": ping_time}
    except requests.RequestException:
        return {"code": 400, "ping_time": ping_time}

def scan_ip(ip, ip_data, file_path):
    """Scan an individual IP for HTTP status, open ports, geolocation, and DNS info, and store the results."""
    print(f"Scanning IP: {ip}")
    
    ip_info = check_ip_with_request(ip)
    open_ports = perform_port_scan(ip, COMMON_PORTS)
    
    if open_ports:
        ip_info["open_ports"] = open_ports
    
    ip_info["geolocation"] = get_geolocation(ip)
    ip_info["dns_info"] = get_dns_info(ip)
    ip_info["isp_info"] = get_isp_info(ip)
    ip_info["response_headers"] = get_response_headers(ip)
    ip_info["ssl_certificate"] = get_ssl_certificate(ip)
    
    timestamp = datetime.now().isoformat()
    ip_info["timestamp"] = timestamp

    with lock:
        ip_data[ip] = ip_info
        # Update the JSON file with the current state of ip_data
        with open(file_path, 'w') as file:
            json.dump(ip_data, file, indent=4)

def save_ip_to_json(file_path, num_ips):
    """Generate and save unique IP addresses and their request status, redirection details, and port scan results to a JSON file."""
    try:
        with open(file_path, 'r') as file:
            ip_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        ip_data = {}

    threads = []
    
    for _ in range(num_ips):
        new_ip = generate_random_ip()
        if new_ip not in ip_data:
            thread = threading.Thread(target=scan_ip, args=(new_ip, ip_data, file_path))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

    print(f"Added {num_ips} IP addresses with HTTP request status, geolocation, DNS info, ISP, SSL, and port scan results to {file_path}.")

i = 1
# runs in batches of 100
while True: 
    if i != 1:
     save_ip_to_json('ips.json', 100)
     print("Taking a break...")
     time.sleep(50)
    
