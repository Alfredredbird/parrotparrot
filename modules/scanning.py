# Function to get geolocation info
import nmap
import requests


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

def scan_ip(ip):
    nm = nmap.PortScanner()
    try:
        # Start the scan with OS detection (-O)
        nm.scan(ip, arguments='-O -sV')
        
        # Ensure the scan has results for the IP address
        if ip in nm.all_hosts():
            host_info = nm[ip]
            result = {
                'ip': ip,
                'hostname': host_info.hostname() or 'N/A',
                'status': host_info.state(),
                'device_type': host_info.get('osclass', [{}])[0].get('type', 'unknown'),
                'ports': []
            }

            # Add port information to the result
            for protocol in host_info.all_protocols():
                ports = host_info[protocol].keys()
                for port in ports:
                    port_info = host_info[protocol][port]
                    result['ports'].append({
                        'port': port,
                        'state': port_info['state'],
                        'service': port_info.get('name', 'unknown')
                    })
            # Add geolocation info
            result['geolocation'] = get_geolocation(ip)
            return result
        else:
            # If no information is available for the IP, return an empty result
            print(f"No information found for IP {ip}.")
            return {}
    
    except Exception as e:
        print(f"Error scanning IP {ip}: {e}")
        return {}
