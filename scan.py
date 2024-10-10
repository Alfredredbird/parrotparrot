import json
import random
import requests
import socket
import threading
import time
import ssl
import argparse
from datetime import datetime

COMMON_PORTS = [21, 22, 23, 25, 80, 443, 8080,7,902,88,23,53,381,69,587,1337,20,1025,102,110,139,135,137,143,465,593,636,691,989,993,995,158,8096]
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

def scan_ip(ip, ip_data):
    """Scan an individual IP for HTTP status, open ports, geolocation, and DNS info, and update the results."""
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

    return ip_info  # Return the IP information to be updated in the main data structure

def save_ip_to_json(file_path, specific_ip):
    """Load existing IP data, scan the specific IP, and update the JSON file."""
    try:
        with open(file_path, 'r') as file:
            ip_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        ip_data = {}

    # Scan the specific IP
    ip_info = scan_ip(specific_ip, ip_data)

    with lock:
        # Update or add the IP information in the data
        ip_data[specific_ip] = ip_info

        # Update the JSON file with the current state of ip_data
        with open(file_path, 'w') as file:
            json.dump(ip_data, file, indent=4)

    print(f"Updated data for IP address: {specific_ip}.")

def main():
    parser = argparse.ArgumentParser(description="IP Scanner")
    parser.add_argument('-ip', type=str, help="Specific IP address to scan.")
    args = parser.parse_args()

    if args.ip:
        save_ip_to_json('ips.json', args.ip)  # Pass the specific IP to scan and save
    else:
        print("No IP address provided to scan.")
    print("Done!")

if __name__ == "__main__":
    main()
