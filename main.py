import json
import random
import requests
import socket
import threading
import time
import ssl
import redis
from datetime import datetime
import nmap

COMMON_PORTS = [21, 22, 23, 25, 80, 443, 8080, 7, 902, 88, 23, 53, 381, 69, 587, 1337, 20, 1025, 102, 110, 139, 135,
                137, 143, 465, 593, 636, 691, 989, 993, 995, 158, 8096]
lock = threading.Lock()

# Initialize Redis connection
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)


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
    except Exception as e:
        return {"error": str(e)}


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


def scan_device_type(ip):
    """Use Nmap to scan an IP for detailed device information and update the Redis entry."""
    try:
        # Initialize the Nmap scanner
        nm = nmap.PortScanner()

        # Scan for detailed information with a timeout of 2 seconds
        nm.scan(ip, arguments='-O -sS', timeout=10)

        # Extract information
        device_info = {}

        # Get device type and OS information
        if 'osclass' in nm[ip]:
            os_info = nm[ip]['osclass']
            device_info["device_type"] = os_info[0]['type'] if os_info else "Unknown"
            device_info["os_family"] = os_info[0]['osfamily'] if os_info else "Unknown"
        else:
            device_info["device_type"] = "Unknown"
            device_info["os_family"] = "Unknown"

        # Get hostnames
        device_info["hostnames"] = nm[ip].hostname() or "Unknown"

        # Get MAC address and vendor
        if 'addresses' in nm[ip] and 'mac' in nm[ip]['addresses']:
            device_info["mac_address"] = nm[ip]['addresses']['mac']
            device_info["vendor"] = nm[ip]['vendor'].get(device_info["mac_address"], "Unknown")
        else:
            device_info["mac_address"] = "Unknown"
            device_info["vendor"] = "Unknown"

        # Get open ports and their services
        if 'tcp' in nm[ip]:
            device_info["open_ports"] = {port: nm[ip]['tcp'][port]['name'] for port in nm[ip]['tcp']}

        if 'udp' in nm[ip]:
            device_info.setdefault("open_ports", {}).update(
                {port: nm[ip]['udp'][port]['name'] for port in nm[ip]['udp']})

        # Lock the thread and update the Redis entry
        with lock:
            # Retrieve current data from Redis
            current_data = json.loads(redis_client.get(f"scan_result:{ip}"))
            current_data.update(device_info)

            # Save updated data back to Redis
            redis_client.set(f"scan_result:{ip}", json.dumps(current_data))

        print(f"Device details for {ip}: {device_info}")

    except Exception as e:
        print(f"Failed to scan device details for {ip}: {e}")


def scan_ip(ip):
    """Scan an individual IP for HTTP status, open ports, geolocation, and DNS info, and store the results in Redis."""
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
        # Store the scan result in Redis
        redis_client.set(f"scan_result:{ip}", json.dumps(ip_info))

    # Run the detailed device scan
    scan_device_type(ip)


def save_ip_to_redis(num_ips):
    """Generate and save unique IP addresses and their scan results to Redis."""
    threads = []

    for _ in range(num_ips):
        new_ip = generate_random_ip()
        if not redis_client.exists(f"scan_result:{new_ip}"):  # Check if IP is already scanned
            thread = threading.Thread(target=scan_ip, args=(new_ip,))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

    print(
        f"Added {num_ips} IP addresses with HTTP request status, geolocation, DNS info, ISP, SSL, and port scan results to Redis.")


start_scanning = False
# runs in batches of 100
while True:
    if start_scanning:
        save_ip_to_redis(100)
        print("Taking a break...")
        time.sleep(50)
