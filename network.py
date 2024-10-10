import json
import threading
from typing import Literal

import nmap
import requests
from faker import Faker

def generate_random_ip(_type: Literal["ipv4", "ipv6"] = "ipv4"):
    fake = Faker()

    # Generate a random IP address based on the given _type
    random_ip = fake.ipv4() if _type == "ipv4" else fake.ipv6()

    return random_ip


def get_geolocation(ip):
    try:
        response = requests.get(f'https://geolocation-db.com/json/{ip}&position=true').json()
        return {
            'country': response.get('country_name'),
            'city': response.get('city'),
            'latitude': response.get('latitude'),
            'longitude': response.get('longitude')
        }
    except Exception as e:
        print(f"Error fetching geolocation for IP {ip}: {e}")
        return {}

def scan_ip(ip, ip_data, file_path):
    nm = nmap.PortScanner()
    
    # Perform a simple Nmap scan to get host details
    try:
        nm.scan(ip, arguments='-O')
        host_info = nm[ip]
        ip_data[ip] = {
            'hostname': host_info.hostname(),
            'status': host_info.state(),
            'device_type': host_info.get('osclass', [{}])[0].get('type', 'unknown'),
            'ports': []
        }

        # Get open ports
        for protocol in host_info.all_protocols():
            ports = host_info[protocol].keys()
            for port in ports:
                port_info = host_info[protocol][port]
                ip_data[ip]['ports'].append({
                    'port': port,
                    'state': port_info['state'],
                    'service': port_info.get('name', 'unknown')
                })

        # Add geolocation data
        ip_data[ip]['geolocation'] = get_geolocation(ip)

        # Save the updated IP data to the JSON file without overwriting existing data
        with open(file_path, 'w') as file:
            json.dump(ip_data, file, indent=4)

    except Exception as e:
        print(f"Error scanning IP {ip}: {e}")

def save_ip_to_json(file_path, num_ips):
    """Generate and save unique IP addresses and their details to a JSON file."""
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

    print(f"Added {num_ips} IP addresses with details to {file_path}.")
