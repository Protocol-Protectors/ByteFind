import requests
from bs4 import BeautifulSoup
import validators
import re
import sys
from urllib.parse import urljoin, urlparse

def format_url(input_value):
    """Formats user input as a valid HTTPS URL if only a domain is given."""
    input_value = input_value.strip()
    # If it starts with http:// or https://, assume it's a full URL
    if input_value.startswith(("http://", "https://")):
        return input_value
    # Otherwise, assume it's a domain and format it properly
    return f"https://{input_value}"

def is_valid_url(url):
    """Checks if the given URL is valid."""
    if validators.url(url):
        return True
    print("Invalid URL or domain. Please enter a valid input (e.g., example.com or https://example.com).")
    return False

def extract_endpoints(url):
    """Crawls the website and extracts internal links, JavaScript files, and potential API endpoints."""
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        if response.status_code != 200:
            print(f" Error: Received status code {response.status_code}")
            return

        soup = BeautifulSoup(response.text, "html.parser")

        internal_links = set()
        js_files = set()
        api_endpoints = set()

        base_domain = urlparse(url).netloc
        # Extract <a> tags (internal links)
        for link in soup.find_all("a", href=True):
            href = link["href"]
            full_url = urljoin(url, href)
            if base_domain in urlparse(full_url).netloc:  # Check if it's internal
                internal_links.add(full_url)
        # Extract <script> tags (JavaScript files)
        for script in soup.find_all("script", src=True):
            src = script["src"]
            full_url = urljoin(url, src)
            js_files.add(full_url)
        # Find potential API endpoints (e.g., URLs containing "/api/", ".json", etc.)
        api_patterns = [r"/api/", r"\.json", r"\.php", r"\.aspx", r"\.jsp"]
        for pattern in api_patterns:
            matches = re.findall(pattern, response.text)
            if matches:
                api_endpoints.add(pattern)

        # Display results
        print(f"\n Crawled {url}\n" + "-" * 50)

        if internal_links:
            print("\n Internal Links Found:")
            for link in internal_links:
                print(f"  - {link}")
        else:
            print("\n No internal links found.")

        if js_files:
            print("\n JavaScript Files Found:")
            for js in js_files:
                print(f"  - {js}")
        else:
            print("\n No JavaScript files found.")

        if api_endpoints:
            print("\n Possible API Endpoints Found:")
            for api in api_endpoints:
                print(f"  - {api}")
        else:
            print("\n No API endpoints found.")

    except requests.exceptions.RequestException as e:
        print(f" Error: Unable to connect to {url}\n{e}")
# Input domain or URL from user
def endpoints(murl):
    try:
        user_input = murl
        target_url = format_url(user_input)  # Convert domain to full URL if needed
        if is_valid_url(target_url):
            extract_endpoints(target_url)
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        sys.exit(1)
if __name__ == "__main__":
    endpoints()