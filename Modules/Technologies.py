import requests
import re
import warnings
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from Wappalyzer import Wappalyzer, WebPage

# Suppress regex warnings from Wappalyzer
warnings.filterwarnings("ignore", category=UserWarning)

def is_valid_url(url):
    """ Validate if the input is a proper domain or URL """
    regex = re.compile(
        r'^(?:(?:http|https)://)?'  # Optional scheme
        r'(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+$'
    )
    return re.match(regex, url) is not None

def get_web_technologies(url):
    """ Identify web technologies and versions using Wappalyzer """
    try:
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()
        technologies = wappalyzer.analyze_with_versions_and_categories(webpage)

        if technologies:
            print("\n--- Identified Technologies & Versions ---")
            for tech, details in technologies.items():
                version = details.get('versions', ['Unknown'])[0] if details.get('versions') else 'Unknown'
                category = details.get('categories', ['Unknown'])[0] if details.get('categories') else 'Unknown'
                print(f"{tech}: Version {version}, Category: {category}")
        else:
            print("No technologies detected.")
    except requests.RequestException as e:
        print(f"Network error detecting technologies: {e}")
    except Exception as e:
        print(f"Unexpected error detecting technologies: {e}")

def extract_metadata(url):
    """ Extract metadata from the webpage using BeautifulSoup """
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; WebScanner/1.0)'}
    try:
        response = requests.get(url, timeout=10, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        title = soup.title.string.strip() if soup.title else "No title found"
        description = soup.find("meta", attrs={"name": "description"})
        description = description["content"].strip() if description else "No description found"

        print("\n--- Page Metadata ---")
        print(f"Title: {title}")
        print(f"Description: {description}")
    except requests.RequestException as e:
        print(f"Error fetching webpage metadata: {e}")

def Web_Technologies(url):
    # Add scheme if missing
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url

    # Validate the final URL
    if is_valid_url(url):
        print(f"\nScanning: {url}")
        get_web_technologies(url)
        extract_metadata(url)
    else:
        print("Invalid URL even after adding https://. Please check the address.")
