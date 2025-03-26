import requests
import re
import os
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
import sys

def is_valid_url(url):
    """Check if the URL/domain is valid"""
    url_pattern = r'^(https?:\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(\/)?$'
    if not url.startswith(('http://','https://')):
        url = 'https://' + url
    return bool(re.match(url_pattern, url)), url

def check_directory(base_url, directory):
    """Check directory existence and HTTP status"""
    full_url = urljoin(base_url, directory)
    try:
        response = requests.get(full_url, timeout=5, allow_redirects=True)
        status_code = response.status_code

        # Modified result based on status code
        if status_code == 200:
            result = "Found"
        elif status_code == 403:
            result = "Not Found"  # Changed from "Found" to "Not Found" for 403
        elif status_code in [301, 302]:
            result = "Redirect"
        else:
            result = f"Not Found"

        return (full_url, status_code, result)
    except requests.ConnectionError:
        return (full_url, "N/A", "Error: Connection refused")  # Changed from "Not Found"
    except requests.Timeout:
        return (full_url, "N/A", "Error: Timeout")  # Changed from "Timeout"
    except requests.RequestException as e:
        return (full_url, "N/A", f"Error: {str(e)}")

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
            cleaned = re.sub(r'^/+|/+$|[<>:"/\\|?*]', '', entry)
            if cleaned and len(cleaned) <= 100:
                valid_entries.append(cleaned)
            else:
                invalid_count += 1

        if not valid_entries:
            print(f"Error: No valid directory names found in '{filename}'")
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

def find_directories():
    """Find subdirectories with prompt-based input"""
    # Get URL from user
    while True:
        url = input("Enter target URL (e.g., example.com or http://example.com): ").strip()
        is_valid, validated_url = is_valid_url(url)
        if is_valid:
            break
        print(f"Error: '{url}' is not a valid URL. Please try again.")

    # Get custom wordlist
    while True:
        wordlist_path = input("Enter path to wordlist file: ").strip()
        directories_to_check = validate_wordlist(wordlist_path)
        if directories_to_check is not None:
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

    # Ensure directories start with / if they don't
    directories_to_check = [d if d.startswith('/') else f'/{d}'
                            for d in directories_to_check]

    # Print header
    print(f"\nScanning directories for {validated_url}")
    print("-" * 70)
    print(f"{'Directory':<40} {'Status':<10} {'Result':<15}")
    print("-" * 70)

    # Use ThreadPoolExecutor for concurrent checking
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        check_params = [(validated_url, dir_path) for dir_path in directories_to_check]
        results = executor.map(lambda p: check_directory(*p), check_params)

        # Process and display results
        for full_url, status_code, result in results:
            status_str = str(status_code) if status_code else "N/A"
            print(f"{full_url:<40} {status_str:<10} {result:<15}")

def subdirectory():
    try:
        find_directories()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    subdirectory()