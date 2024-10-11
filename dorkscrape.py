from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import time
import json

# Configure Chrome options
chrome_options = Options()
chrome_options.add_argument("--headless")  # Run in headless mode (no GUI)
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")

# Start the WebDriver
driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

# Function to perform Google search
def google_search(query):
    # Open Google and search for the query
    search_url = f"https://www.google.com/search?q={query}"
    driver.get(search_url)
    time.sleep(2)  # Wait for page to load

    # Parse the HTML
    soup = BeautifulSoup(driver.page_source, 'html.parser')

    # Extract search results
    results = []
    for result in soup.find_all('div', class_='g'):
        link = result.find('a')['href']
        title = result.find('h3').text if result.find('h3') else 'No title'
        results.append({'title': title, 'link': link})

    return results

# Save results to a JSON file
def save_to_json(data, filename="urls.json"):
    try:
        with open(filename, 'w') as file:
            json.dump(data, file, indent=4)
        print(f"Data successfully saved to {filename}")
    except IOError as e:
        print(f"An error occurred while saving to file: {e}")

# Example camera dork query
dork_query = 'inurl:/view/view.shtml'

# Run the search
results = google_search(dork_query)

# Print the search results
for i, result in enumerate(results):
    print(f"{i+1}. {result['title']}: {result['link']}")

# Save the URLs to urls.json
save_to_json(results)

# Close the WebDriver
driver.quit()
