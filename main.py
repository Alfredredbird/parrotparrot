import json
import random
import requests
import socket
import threading
import time
from datetime import datetime  # Import datetime for date and time handling

# Define common ports for a quick scan (HTTP, HTTPS, FTP, SSH, etc.)
COMMON_PORTS = [21, 22, 23, 25, 80, 443, 8080]

# Lock to ensure thread-safe access to shared resources
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

def check_ip_with_request(ip):
    """Check if an IP is reachable and handle redirection. Return status code, redirected URL if any, ping time, and timestamp."""
    start_time = time.time()  # Start time for ping measurement
    try:
        response = requests.get(f"http://{ip}", timeout=1, allow_redirects=True)
        
        if response.history:
            redirect_url = response.url
            ping_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            return {"code": response.status_code, "redirected_to": redirect_url, "ping_time": ping_time}
        else:
            ping_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            return {"code": response.status_code, "ping_time": ping_time}
    except requests.RequestException:
        return {"code": 400, "ping_time": None}  # Treat all connection errors as failure

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

def scan_ip(ip, ip_data, file_path):
    """Scan an individual IP for HTTP status, open ports, geolocation, and DNS info, and store the results."""
    print(f"Scanning IP: {ip}")  # Print out the IP being scanned
    
    # Check if IP is reachable and get HTTP status
    ip_info = check_ip_with_request(ip)
    
    # Perform a fast port scan on common ports
    open_ports = perform_port_scan(ip, COMMON_PORTS)
    if open_ports:
        ip_info["open_ports"] = open_ports

    # Get geolocation and DNS information
    ip_info["geolocation"] = get_geolocation(ip)
    ip_info["dns_info"] = get_dns_info(ip)

    # Save the current date and time
    timestamp = datetime.now().isoformat()  # ISO format for easy parsing
    ip_info["timestamp"] = timestamp

    # Store the results in the shared data structure using a lock for thread safety
    with lock:
        ip_data[ip] = ip_info
        
        # Save the updated data to the JSON file
        with open(file_path, 'w') as file:
            json.dump(ip_data, file, indent=4)

def save_ip_to_json(file_path, num_ips):
    """Generate and save unique IP addresses and their request status, redirection details, and port scan results to a JSON file."""
    # Load existing IP addresses from the JSON file, if it exists
    try:
        with open(file_path, 'r') as file:
            ip_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        ip_data = {}

    threads = []
    
    # Generate and save unique IPs with their request status, redirection details, and port scan results
    for _ in range(num_ips):
        new_ip = generate_random_ip()
        
        # Only scan if IP is not already in the data
        if new_ip not in ip_data:
            thread = threading.Thread(target=scan_ip, args=(new_ip, ip_data, file_path))
            threads.append(thread)
            thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    print(f"Added {num_ips} IP addresses with HTTP request status, geolocation, DNS info, and port scan results to {file_path}.")

# Example usage:
save_ip_to_json('ips.json', 100)
