import requests
import validators
import sys
# List of important security headers
SECURITY_HEADERS = [
    "Strict-Transport-Security",  # Protects against MITM attacks (HSTS)
    "Content-Security-Policy",  # Prevents XSS attacks
    "X-Frame-Options",  # Prevents clickjacking attacks
    "X-Content-Type-Options",  # Prevents MIME-sniffing attacks
    "Referrer-Policy",  # Controls referrer information sent
    "Permissions-Policy",  # Controls browser features like camera/mic
    "Cross-Origin-Resource-Policy",  # Restricts resource sharing
    "Cross-Origin-Opener-Policy"  # Prevents cross-origin attacks
]

def format_url(input_value):
    """Formats user input as a valid HTTPS URL if only a domain is given."""
    input_value = input_value.strip()  # Remove spaces

    # If it starts with http:// or https://, assume it's a full URL
    if input_value.startswith(("http://", "https://")):
        return input_value

    # Otherwise, assume it's a domain and format it properly
    return f"https://{input_value}"

def is_valid_url(url):
    """Checks if the given URL is valid."""
    if validators.url(url):
        return True
    print(" Invalid URL or domain. Please enter a valid input (e.g., example.com or https://example.com).")
    return False

def check_security_headers(url):
    """Checks the security headers of a given URL."""
    try:
        response = requests.get(url, timeout=5)  # Send HTTP request
        headers = response.headers  # Extract response headers

        print(f"\n Security Headers for {url}:\n" + "-" * 50)

        missing_headers = []
        for header in SECURITY_HEADERS:
            if header in headers:
                print(f" {header}: {headers[header]}")
            else:
                print(f" {header} - MISSING")
                missing_headers.append(header)

        if missing_headers:
            print("\n Missing Security Headers:")
            for header in missing_headers:
                print(f"    {header}")

    except requests.exceptions.RequestException as e:
        print(f" Error: Unable to connect to {url}\n{e}")

# Input domain or URL from user
def security_headers(murl):
    try:
        user_input = murl
        target_url = format_url(user_input)  # Convert domain to full URL if needed
        if is_valid_url(target_url):
            check_security_headers(target_url)
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        sys.exit(1)
if __name__ == "__main__":
    security_headers()