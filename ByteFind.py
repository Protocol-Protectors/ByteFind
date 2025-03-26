import pyfiglet
import sys
from Modules.dns_lookup import dns_whois_module  # Importing dns_lookup.py to access its functions
from Modules.Technologies import Web_Technologies # Importing Technologies.py to access its functions
from Modules.Detect_WAF import WAF  # Importing Detect_WAF.py to access its functions
from Modules.cve import cve  # Importing cve.py
from Modules.origin import origin  # Importing origin.py
from Modules.subdomains import subdomains  # Importing subdomains.py to access its functions
from Modules.subdirectory import subdirectory  # Importing subdirectory.py to access its functions
from Modules.security_headers import security_headers  # Importing security_headers.py to access its functions
from Modules.End_Point import endpoints  # Importing End_Point.py to access its functions
from Modules.status_code import status_code  # Importing status_code.py to access its functions
from Modules.google_dork import google_dork  # Importing google_dork.py to access its functions
from Modules.OS import OS  # Importing OS.py
from Modules.Port_scan import Port_scan  # Importing Port_scan.py to access its functions
from Modules.Metasploit import Metasploit_scan  # Importing Metasploit.py

def main_menu():
    ascii_banner = pyfiglet.figlet_format("Byte Find")
    print(ascii_banner)
    print("1️⃣ Web Application  Scanning")
    print("2️⃣ Network Scanning")
    choice = input("Select an option (1 or 2): ")

    if choice == "1":
        web_scanning_menu()
    elif choice == "2":
        ip_scanning_menu()
    else:
        print("Invalid choice. Exiting...")
        sys.exit()

def web_scanning_menu():
    print("\n--- Web Application  Scanning ---")
    submodules = {
        "1.1": "DNS and WHOIS Information",
        "1.2": "Identify Web Technologies & Versions",
        "1.3": "Detect WAF (Web Application Firewall)",
        "1.4": "Search for CVEs Based on Detected Versions",
        "1.5": "Find the Origin IP & Check the IP Response",
        "1.6": "Find Subdomains",
        "1.7": "Find Subdirectories",
        "1.8": "Find the Security Headers",
        "1.9": "Website Crawl and End Point Detection",
        "1.10": "Web Status Checker",
        "1.11": "Google Dork"
    }
    for key, value in submodules.items():
        print(f"{key} {value}")
    sub_choice = input("Select a module (e.g., 1.1): ")

    if sub_choice == "1.1":
        print("\nRunning DNS and WHOIS Lookup...")
        dns_whois_module()
    elif sub_choice == "1.2":
        print("\nRunning Web Technologies Identification...")
        url = input("Enter a website URL (e.g., https://example.com): ").strip()
        Web_Technologies(url)
    elif sub_choice == "1.3":
        print("\nDetecting Web Application Firewall (WAF)...")
        url = input("Enter a website URL (e.g., https://example.com): ").strip()
        result = WAF(url)
    elif sub_choice == "1.4":
        print("\nSearching for CVEs Based on Detected Versions...")
        cve()  # Call the main function from cve.py
    elif sub_choice == "1.5":
        print("\nFinding the Origin IP & Checking Response...")
        origin()  # Call the main function from origin.py
    elif sub_choice == "1.6":
        print("\nFinding Subdomains...")
        subdomains()
    elif sub_choice == "1.7":
        print("\nFinding Subdirectories...")
        subdirectory()
    elif sub_choice == "1.8":
        print("\nChecking Security Headers...")
        url = input("Enter a website URL (e.g., https://example.com): ").strip()
        security_headers(url)
    elif sub_choice == "1.9":
        print("\nCrawling Website for End Points...")
        url = input("Enter a website URL (e.g., https://example.com): ").strip()
        endpoints(url)
    elif sub_choice == "1.10":
        print("\nChecking Web Status...")
        status_code()
    elif sub_choice == "1.11":
        print("\nPerforming Google Dorking...")
        google_dork()
    else:
        print("Invalid choice. Returning to main menu.")
        main_menu()

def ip_scanning_menu():
    print("\n---  Network Scanning  ---")
    submodules = {
        "2.1": "Find the OS & Version",
        "2.2": "Find Open Ports, Services, and Versions",
        "2.3": "Identify Common Vulnerabilities Using Service and Version"
    }
    for key, value in submodules.items():
        print(f"{key} {value}")
    sub_choice = input("Select a module (e.g., 2.1): ")

    if sub_choice == "2.1":
        print("\nFinding the OS & Version...")
        target_ip = input("Enter the target IP address (e.g., 127.0.0.1): ").strip()
        print(OS(target_ip))
    if sub_choice == "2.2":
        print("\nScanning Open Ports, Services, and Versions...")
        try:
          Port_scan()
        except Exception as e :
         print("Invalid choice! Returning to menu.")
         ip_scanning_menu()
    elif sub_choice == "2.3":
        print("\nIdentifying Common Vulnerabilities Using Service and Version...")
        try:
          Metasploit_scan() # Call the main function from Metasploit.py
        except Exception as e :
         print("Invalid choice! Returning to menu.")
         ip_scanning_menu()
    else:
        print("Invalid choice. Returning to main menu.")
        main_menu()

if __name__ == "__main__":
    main_menu()
