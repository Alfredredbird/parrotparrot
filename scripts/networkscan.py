import nmap
import json
import os
import socket
import ipaddress
from datetime import datetime

# Function to check if a key exists in a dictionary
def update_json_file(file_path, new_data):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            existing_data = json.load(f)
    else:
        existing_data = {}

    # Update or add the new data
    existing_data.update(new_data)

    # Save the updated data back to the file
    with open(file_path, 'w') as f:
        json.dump(existing_data, f, indent=4)

# Function to get the local IP address
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))  # An unreachable address will work for getting the local IP
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'  # Fallback to localhost if no network interface found
    finally:
        s.close()
    return local_ip

# Function to detect the network range based on the local IP address
def get_network_range(local_ip):
    # Parse the local IP address
    ip_obj = ipaddress.IPv4Address(local_ip)

    # Get the network range (assume /24 subnet mask by default for home networks)
    network_obj = ipaddress.IPv4Network(f'{local_ip}/24', strict=False)
    
    return str(network_obj.network_address) + '/24'  # e.g., 192.168.12.0/24

# Function to perform a network scan using Nmap
def network_scan(network_range):
    nm = nmap.PortScanner()  # Instantiate the PortScanner here
    print(f"Scanning network range: {network_range}")
    try:
        # Increased timeout to 30 seconds to avoid premature timeout
        nm.scan(hosts=network_range, arguments='-O')  # -O for OS detection
        return nm.all_hosts(), nm
    except nmap.nmap.PortScannerTimeout:
        print("Timeout reached during the scan.")
        return [], nm
    except Exception as e:
        print(f"An error occurred during the scan: {e}")
        return [], nm

# Function to extract detailed information about the host
def get_host_info(host, nm):
    print(f"Scanning host: {host}")
    info = {
        "code": 200,
        "ping_time": None,
        "open_ports": [],
        "geolocation": {},  # Dummy data for now
        "dns_info": {},  # Dummy data for now
        "isp_info": "",  # Dummy data for now
        "response_headers": {},  # Dummy data for now
        "ssl_certificate": {},  # Dummy data for now
        "timestamp": datetime.now().isoformat(),
        "device_type": "unknown",  # Default device type
    }

    # Extracting the ping time and open ports
    if host in nm.all_hosts():
        host_info = nm[host]
        info["ping_time"] = host_info.get('hostnames', [])

        # Safely get open TCP ports
        tcp_ports = host_info.get('tcp', {})
        info["open_ports"] = list(tcp_ports.keys())  # Open TCP ports

    # Get OS information
    os_info = nm[host].get('osmatch', [])
    if os_info:
        info["os"] = os_info[0]['name']

    # If no device type is found, use the OS as the device type
    if info["device_type"] == "unknown" and 'os' in info:
        info["device_type"] = info["os"]

    return {host: info}


# Main scanning and saving function
def scan_and_save(network_range, file_path):
    hosts, nm = network_scan(network_range)  # Pass nm along with hosts
    for host in hosts:
        host_info = get_host_info(host, nm)
        update_json_file(file_path, host_info)

# Get the local IP and determine the network range
local_ip = get_local_ip()
print(f"Local IP: {local_ip}")

network_range = get_network_range(local_ip)
print(f"Network range: {network_range}")

file_path = 'saves/ips.json'

# Perform the scan and save the results
scan_and_save(network_range, file_path)
print("Network scan complete and data saved.")
