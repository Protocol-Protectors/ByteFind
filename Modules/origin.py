import socket
import requests
import re
import subprocess
import platform
from urllib.parse import urlparse
import dns.resolver
from censys.search import CensysHosts

# Function to validate domain
def is_valid_domain(domain):
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, domain))

# Function to validate URL
def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

# Function to get IP from DNS resolution
def get_origin_ip_dns(domain):
    try:
        domain = domain.replace('http://', '').replace('https://', '').replace('www.', '')
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

# Function to get the real origin IP using Censys API
def get_censys_origin_ip(api_id, api_secret, domain):
    try:
        censys_client = CensysHosts(api_id, api_secret)
        query = f"services.tls.certificates.leaf_data.subject_dn='CN={domain}'"
        results = censys_client.search(query, per_page=1)

        if results:
            for result in results:
                return result["ip"]
    except Exception as e:
        print(f"\n[Censys Error] {e}")
    return None

# Function to get the origin IP using Ping (Cross-Platform)
def get_origin_ip_ping(domain):
    try:
        # Check OS type
        system_os = platform.system()

        if system_os == "Windows":
            ping_cmd = ["ping", "-n", "1", domain]
        else:
            ping_cmd = ["ping", "-c", "1", domain]

        # Run ping command
        ping_output = subprocess.check_output(ping_cmd, stderr=subprocess.DEVNULL, text=True)

        # Extract IP address from the output
        match = re.search(r'PING.*\(([\d\.]+)\)', ping_output)
        if match:
            return match.group(1)

    except subprocess.CalledProcessError:
        return None  # Ping failed
    except Exception as e:
        print(f"[Ping Error] {e}")
        return None

# Function to check response code of an IP
def check_ip_response(ip):
    try:
        response = requests.get(f'http://{ip}', timeout=5)
        return response.status_code
    except requests.RequestException:
        try:
            response = requests.get(f'https://{ip}', timeout=5)
            return response.status_code
        except requests.RequestException:
            return None

# Function to check if an IP is directly accessible
def check_access(response_code):
    return response_code == 200

# Function to get all A records of a domain
def get_additional_ips(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [str(answer) for answer in answers]
    except Exception:
        return []

# Main function
def origin():

    # Get user input for Censys API credentials
    censys_api_id = input("Enter your Censys API ID: ").strip()
    censys_api_secret = input("Enter your Censys API Secret: ").strip()
    # Get input from user
    input_str = input("Please enter a domain or URL: ").strip()
    # Validate input
    domain = input_str
    if is_valid_url(input_str):
        parsed_url = urlparse(input_str)
        domain = parsed_url.netloc
    elif not is_valid_domain(domain):
        print("Invalid domain or URL format!")
        return
    print(f"\nProcessing: {domain}")
    # Get origin IP via DNS
    dns_ip = get_origin_ip_dns(domain)
    if dns_ip:
        print(f"[DNS] Origin IP: {dns_ip}")
    else:
        print("[DNS] Could not resolve IP address.")

    # Get real Origin IP from Censys
    censys_ip = get_censys_origin_ip(censys_api_id, censys_api_secret, domain)
    if censys_ip:
        print(f"[Censys] Real Origin IP: {censys_ip}")

    # Get Origin IP via Ping
    ping_ip = get_origin_ip_ping(domain)
    if ping_ip:
        print(f"[Ping] Origin IP: {ping_ip}")

    # Determine best available IP for scanning
    origin_ip = censys_ip or dns_ip or ping_ip
    if origin_ip:
        print(f"\nUsing IP for scanning: {origin_ip}")

        response_code = check_ip_response(origin_ip)
        if response_code:
            print(f"Response Code: {response_code}")
        else:
            print("Response Code: N/A")

        # Check direct access
        accessible = check_access(response_code)
        print(f"Direct IP Access: {'Yes' if accessible else 'No'}")

        # Get additional A records
        additional_ips = get_additional_ips(domain)
        if additional_ips:
            print("\nAdditional IP addresses found:")
            for ip in additional_ips:
                if ip != origin_ip:
                    print(f"- {ip}")
                    resp = check_ip_response(ip)
                    access = check_access(resp)
                    print(f"  Response Code: {resp if resp else 'N/A'}")
                    print(f"  Accessible: {'Yes' if access else 'No'}")
        else:
            print("No additional IP addresses found")

    else:
        print("\n[Error] Could not determine the Origin IP.")

if __name__ == "__main__":
    try:
        origin()
    except ImportError as e:
        print(f"Error: Missing required library - {e}")
        print("Please install required libraries using:")
        print("pip install requests dnspython censys")