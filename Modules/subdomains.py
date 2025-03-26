import requests
import re
import os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import sys

def is_valid_domain(domain):
    """Check if the domain/URL is valid"""
    # Regular expression for domain validation
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

    # If it's a full URL, extract the domain
    if domain.startswith('http://') or domain.startswith('https://'):
        domain = urlparse(domain).netloc

    return bool(re.match(domain_pattern, domain)), domain

def check_subdomain(base_domain, subdomain_prefix):
    """Check subdomain availability and HTTP status"""
    full_subdomain = f"{subdomain_prefix}.{base_domain}"
    url = f"http://{full_subdomain}"
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        return (full_subdomain, response.status_code, "Active")
    except requests.ConnectionError:
        return (full_subdomain, None, "Not Active")
    except requests.Timeout:
        return (full_subdomain, None, "Timeout")
    except requests.RequestException as e:
        return (full_subdomain, None, f"Error: {str(e)}")

def validate_wordlist(filename):
    """Validate and load wordlist from file"""
    if not os.path.exists(filename):
        print(f"Error: Wordlist file '{filename}' not found")
        return None

    if os.path.getsize(filename) == 0:
        print(f"Error: Wordlist file '{filename}' is empty")
        return None

    try:
        with open(filename, 'r') as file:
            entries = [line.strip() for line in file if line.strip()]

        if not entries:
            print(f"Error: Wordlist file '{filename}' contains no valid entries")
            return None

        valid_entries = []
        invalid_count = 0

        for entry in entries:
            # Clean subdomain prefix: allow letters, numbers, hyphens only
            cleaned = re.sub(r'[^a-zA-Z0-9-]', '', entry)
            if cleaned and len(cleaned) <= 63:  # Max length for subdomain
                valid_entries.append(cleaned)
            else:
                invalid_count += 1

        if not valid_entries:
            print(f"Error: No valid subdomain prefixes found in '{filename}'")
            return None

        print(f"Wordlist '{filename}' loaded successfully:")
        print(f"- Total entries: {len(entries)}")
        print(f"- Valid entries: {len(valid_entries)}")
        if invalid_count > 0:
            print(f"- Invalid entries skipped: {invalid_count}")

        return valid_entries

    except Exception as e:
        print(f"Error reading wordlist '{filename}': {str(e)}")
        return None

def find_subdomains():
    """Find subdomains with prompt-based input"""
    # Get domain from user
    while True:
        domain = input("Enter target domain (e.g., example.com or http://example.com): ").strip()
        is_valid, validated_domain = is_valid_domain(domain)
        if is_valid:
            break
        print(f"Error: '{domain}' is not a valid domain. Please try again.")

    # Get custom wordlist
    while True:
        wordlist_path = input("Enter path to wordlist file: ").strip()
        subdomains_to_check = validate_wordlist(wordlist_path)
        if subdomains_to_check is not None:
            break
        print("Please provide a valid wordlist file.")

    # Get number of threads
    while True:
        try:
            max_workers = input("Enter number of threads (default 10): ").strip()
            max_workers = int(max_workers) if max_workers else 10
            if max_workers > 0:
                break
            print("Please enter a positive number.")
        except ValueError:
            print("Please enter a valid number.")

    # Print header
    print(f"\nScanning subdomains for {validated_domain}")
    print("-" * 60)
    print(f"{'Subdomain':<35} {'Status':<10} {'Result':<15}")
    print("-" * 60)

    # Use ThreadPoolExecutor for concurrent checking
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        check_params = [(validated_domain, prefix) for prefix in subdomains_to_check]
        results = executor.map(lambda p: check_subdomain(*p), check_params)

        # Process and display results
        for subdomain, status_code, result in results:
            status_str = str(status_code) if status_code else "N/A"
            print(f"{subdomain:<35} {status_str:<10} {result:<15}")

def subdomains():
    try:
        find_subdomains()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        sys.exit(1)
if __name__ == "__main__":
    subdomains()
