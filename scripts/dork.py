import re
import json
import os
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By  # Import By
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import time
from datetime import datetime

# Configure Chrome options
chrome_options = Options()
chrome_options.add_argument("--headless")  # Run in headless mode (no GUI)
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")

# Start the WebDriver
driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

# Function to perform Google search and handle pagination
def google_search(query, pages=5, delay=5):
    search_url = f"https://www.google.com/search?q={query}"
    driver.get(search_url)
    time.sleep(2)  # Wait for the first page to load

    all_results = []

    for page in range(pages):
        soup = BeautifulSoup(driver.page_source, 'html.parser')

        # Extract results from the current page
        for result in soup.find_all('div', class_='g'):
            link = result.find('a')['href']
            title = result.find('h3').text if result.find('h3') else 'No title'
            all_results.append({'title': title, 'link': link})

        # Find the "Next" button and click it
        try:
            next_button = driver.find_element(By.ID, 'pnnext')  # Updated to use By.ID
            next_button.click()
            time.sleep(delay)  # Pause before scraping the next page
        except Exception as e:
            print(f"No more pages or error occurred: {e}")
            break  # No more pages, exit the loop

    return all_results

# Function to extract IPs from links
def extract_ips_from_links(links):
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    ips = set()  # Using a set to avoid duplicates
    for link in links:
        ip_match = ip_pattern.search(link['link'])
        if ip_match:
            ips.add(ip_match.group())
    return ips

# Function to load existing ips.json or create a new structure if it doesn't exist
def load_ips_json(filepath='saves/ips.json'):
    if os.path.exists(filepath):
        with open(filepath, 'r') as file:
            return json.load(file)
    else:
        return {}

# Function to save new IPs to ips.json without overwriting
def save_ips_to_json(new_ips, filepath='saves/ips.json'):
    current_data = load_ips_json(filepath)
    
    for ip in new_ips:
        if ip not in current_data:
            # Add new IP entry with "ip_camera" device type
            current_data[ip] = {
                "code": 400,
                "ping_time": None,
                "open_ports": [],
                "geolocation": {},  # Placeholder for geolocation data
                "dns_info": {},
                "isp_info": "Unknown ISP",
                "response_headers": {},
                "ssl_certificate": {},
                "timestamp": datetime.utcnow().isoformat(),
                "device_type": "ip_camera"  # Set device type to "ip_camera"
            }

    # Write back the updated data to the file
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as file:
        json.dump(current_data, file, indent=4)
    print(f"IPs saved to {filepath}")

# Example camera dork query
dork_query = 'inurl:/view/view.shtml'

# Run the search, scrape 5 pages with a 5-second break between each
results = google_search(dork_query, pages=5, delay=5)

# Extract IPs from the search results
extracted_ips = extract_ips_from_links(results)

# Save the IPs to saves/ips.json with device type as "ip_camera"
save_ips_to_json(extracted_ips)

# Close the WebDriver
driver.quit()
