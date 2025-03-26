import requests
import re
from bs4 import BeautifulSoup
from Wappalyzer import Wappalyzer, WebPage
# Function to extract meta tags for technology & version detection
def extract_meta_technologies(url):
    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(response.text, 'html.parser')

        technologies = {}

        # Check for meta generator tags (commonly used by CMS)
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator:
            content = meta_generator.get('content', '')
            tech_match = re.search(r'([\w\s]+)\s*(\d+\.\d+(\.\d+)?)?', content)
            if tech_match:
                tech_name = tech_match.group(1).strip()
                tech_version = tech_match.group(2) if tech_match.group(2) else "unknown"
                technologies[tech_name] = tech_version

        return technologies

    except requests.RequestException:
        return {}

# Function to detect technologies using Wappalyzer
def detect_technologies(url):
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        detected_tech = wappalyzer.analyze_with_versions_and_categories(webpage)
        return detected_tech
    except Exception as e:
        print(f"[Wappalyzer Error] {e}")
        return {}

# Function to find CVEs based on detected technologies
def search_cve(technology, version):
    try:
        cve_url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={technology}+{version}"
        response = requests.get(cve_url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        cves = []
        for link in soup.find_all("a", href=True):
            if "CVE-" in link.text:
                cves.append(link.text)

        return cves[:5]  # Return top 5 CVEs
    except requests.RequestException:
        return []

# Main function
def cve():
    url = input("Enter the website URL (e.g., https://example.com): ").strip()

    if not url.startswith("http"):
        url = "https://" + url  # Auto-correct if protocol is missing

    print("\n[+] Scanning website for technologies...")

    # Detect technologies
    wappalyzer_tech = detect_technologies(url)
    meta_tech = extract_meta_technologies(url)

    # Merge results
    detected_technologies = {**wappalyzer_tech, **meta_tech}

    if detected_technologies:
        print("\n[+] Detected Technologies & Versions:")
        for tech, details in detected_technologies.items():
            version = details if isinstance(details, str) else details.get("version", "unknown")
            print(f"  - {tech}: {version}")

        # Search for CVEs
        print("\n[+] Searching for CVEs...")
        for tech, details in detected_technologies.items():
            version = details if isinstance(details, str) else details.get("version", "unknown")
            cves = search_cve(tech, version)

            if cves:
                print(f"  - {tech} {version}:")
                for cve in cves:
                    print(f"    - {cve}")
            else:
                print(f"  - No CVEs found for {tech} {version}.")
    else:
        print("\n[!] No technologies detected.")

if __name__ == "__main__":
    try:
        cve()
    except ImportError as e:
        print(f"Error: Missing required library - {e}")
        print("Please install required libraries using:")
        print("pip install requests beautifulsoup4 wappalyzer python-wappalyzer")
