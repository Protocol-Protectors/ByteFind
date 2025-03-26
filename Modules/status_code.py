import requests
import re
import os
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the specific InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def validate_file(file_path):
    """Validates if the file exists and has the correct format"""
    if not os.path.exists(file_path):
        return False, "File not found"

    if not file_path.endswith('.txt'):
        return False, "File must be a .txt file"

    return True, "File is valid"

def normalize_url(url):
    """Converts domain names to URLs with proper scheme"""
    url = url.strip()

    # Check if URL has a scheme, if not add https://
    if not url.startswith(('http://', 'https://')):
        # Basic domain pattern check
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(domain_pattern, url):
            url = f"https://{url}"
        else:
            return None  # Invalid URL format

    return url

def get_website_info(url):
    """Gets status code, content-length, and title for a given URL"""
    try:
        # Add user-agent header to avoid being blocked
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        # Make request with a timeout
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        status_code = response.status_code

        # Get content length
        content_length = response.headers.get('Content-Length', 'Unknown')
        if content_length == 'Unknown' and response.content:
            content_length = len(response.content)

        # Get page title
        title = "No title found"
        if response.text:
            soup = BeautifulSoup(response.text, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                title = title_tag.text.strip()
        return {
            'url': url,
            'status_code': status_code,
            'content_length': content_length,
            'title': title
        }
    except requests.exceptions.RequestException as e:
        return {
            'url': url,
            'status_code': 'Error',
            'content_length': 'N/A',
            'title': f"Error: {str(e)}"
        }

def process_urls(file_path, num_threads, status_filter=None):
    """Process URLs from the file using multiple threads with optional status filter"""
    try:
        valid, message = validate_file(file_path)
        if not valid:
            print(f"Error: {message}")
            return

        with open(file_path, 'r') as file:
            urls = file.readlines()

        # Remove empty lines and normalize URLs
        urls = [normalize_url(url) for url in urls if url.strip()]
        urls = [url for url in urls if url]  # Remove None values

        if not urls:
            print("No valid URLs found in the file.")
            return

        results = []

        filter_message = "all status codes"
        if status_filter:
            filter_message = f"status code(s): {', '.join(map(str, status_filter))}"

        print(f"\nProcessing {len(urls)} URLs with {num_threads} threads...")
        print(f"Filtering for {filter_message}")
        print("=" * 50)

        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            # Map the get_website_info function to all URLs
            future_to_url = {executor.submit(get_website_info, url): url for url in urls}

            # Process the results as they complete
            for future in future_to_url:
                try:
                    result = future.result()

                    # Only add results that match the status filter (if provided)
                    if status_filter is None or str(result['status_code']) in status_filter:
                        results.append(result)
                        print(f"Processed: {result['url']} - Status: {result['status_code']} - Content Length: {result['content_length']} - Title: {result['title']} - MATCH")
                    else:
                        print(f"Processed: {result['url']} - Status: {result['status_code']}")

                except Exception as e:
                    print(f"Error processing URL: {future_to_url[future]} - {str(e)}")

        if not results:
            print(f"\nNo URLs found with the specified status code(s): {', '.join(map(str, status_filter))}")
            return

        # Sort results by status code
        results.sort(key=lambda x: str(x['status_code']))

        # Generate output filename based on filter
        if status_filter:
            filter_suffix = "_status_" + "_".join(map(str, status_filter))
        else:
            filter_suffix = "_all"

        # Write results to output file
        output_file = f"{os.path.splitext(file_path)[0]}{filter_suffix}_results.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"{'URL':<50} | {'Status Code':<15} | {'Content Length':<15} | {'Title':<50}\n")
            f.write("-" * 135 + "\n")
            for result in results:
                f.write(
                    f"{result['url'][:50]:<50} | {result['status_code']:<15} | {result['content_length']:<15} | {result['title'][:50]}\n")

        print("\n" + "=" * 50)
        print(f"Found {len(results)} URLs with the specified status code,content length,and title")
        print(f"Results saved to {output_file}")

    except Exception as e:
        print(f"Error: {str(e)}")

def status_code():
    # Get input file path from user
    while True:
        file_path = input("\nEnter the path to your TXT file containing URLs (one URL per line): ")
        valid, message = validate_file(file_path)
        if valid:
            break
        print(f"Error: {message}. Please try again.")
    # Get number of threads from user
    while True:
        try:
            num_threads = input("\nEnter the number of threads to use (default is 5): ")
            if not num_threads.strip():
                num_threads = 5
                break
            num_threads = int(num_threads)
            if num_threads <= 0:
                print("Please enter a positive number.")
                continue
            break
        except ValueError:
            print("Please enter a valid number.")

    # Get status code filter from user
    status_filter = input("\nEnter specific HTTP status code(s) to filter for (comma-separated, leave blank for all): ")
    if status_filter.strip():
        try:
            # Parse comma-separated status codes
            status_filter = [code.strip() for code in status_filter.split(',')]

            # Validate each status code
            for code in status_filter:
                if not (code.isdigit() or code == "Error"):
                    print(f"Warning: '{code}' is not a valid HTTP status code. Including it anyway.")
        except:
            print("Error parsing status codes. Proceeding without filter.")
            status_filter = None
    else:
        status_filter = None

    # Process the URLs
    process_urls(file_path, num_threads, status_filter)

if __name__ == "__main__":
    status_code()