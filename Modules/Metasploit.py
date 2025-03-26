import nmap
import subprocess

def scan_ports(ip, port_range="1-65535"):
    """ Scan a single IP for open ports, services, and versions """
    nm = nmap.PortScanner()
    nm.scan(ip, port_range, arguments='-sV --script vuln')  # -sV for version, --script vuln for vulnerability scan
    open_ports = {}

    if ip in nm.all_hosts():
        for port in nm[ip]['tcp']:
            if nm[ip]['tcp'][port]['state'] == 'open':
                service = nm[ip]['tcp'][port].get('name', 'Unknown')
                product = nm[ip]['tcp'][port].get('product', 'Unknown')
                version = nm[ip]['tcp'][port].get('version', 'Unknown')
                extra_info = nm[ip]['tcp'][port].get('extrainfo', '')

                service_details = f"{product} {version} {extra_info}".strip()
                open_ports[port] = {"service": service, "details": service_details}

    return open_ports, nm  # Return Nmap results for vulnerabilities
def scan_range(network, port_range="1-65535"):
    """ Scan a range of IPs for live hosts """
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')  # -sn: Ping scan to discover live hosts

    live_hosts = [host for host in nm.all_hosts()]

    print("\nLive Hosts Found:")
    for host in live_hosts:
        print(host)

    for ip in live_hosts:
        print(f"\nScanning {ip} for open ports and vulnerabilities...")
        open_ports, scan_data = scan_ports(ip, port_range)

        if open_ports:
            display_results(ip, open_ports, scan_data)
        else:
            print("No open ports found.")

def search_metasploit(service, version):
    """ Searches for Metasploit exploits related to the given service and version """
    print(f"\n Searching for Metasploit exploits related to {service} {version}...\n")

    try:
        result = subprocess.run(
            ["msfconsole", "-q", "-x", f"search {service} {version}; exit"],
            capture_output=True,
            text=True
        )
        print(result.stdout)
    except Exception as e:
        print(f" Error running Metasploit search: {e}")

def search_exploits(open_ports):
    """ Searches for Metasploit exploits for detected services """
    for port, details in open_ports.items():
        service_version = details['details'].split()  # Split service and version
        if len(service_version) > 1:
            service, version = service_version[0], service_version[1]
            search_metasploit(service, version)
        else:
            print(f"\n Skipping Metasploit search for '{details['service']}' (version unknown).")

def display_results(ip, open_ports, scan_data):
    """ Displays Open Ports, Vulnerabilities, and Metasploit Exploits in order """

    # Step 1: Open Ports & Services
    print(f"\n Open Ports & Services on {ip}:")
    for port, details in open_ports.items():
        print(f"Port {port}: {details['service']} - {details['details']}")

    # Step 2: Vulnerability Scan Results
    print("\n  Vulnerabilities Detected:")
    vuln_found = False
    for port in open_ports:
        if 'script' in scan_data[ip]['tcp'][port]:
            vuln_found = True
            print(f"\n Port {port} ({open_ports[port]['service']}) Vulnerabilities:")
            for script, output in scan_data[ip]['tcp'][port]['script'].items():
                print(f"  [{script}] {output}")

    if not vuln_found:
        print(" No known vulnerabilities detected.")

    # Step 3: Metasploit Exploit Search
    search_exploits(open_ports)

def Metasploit_scan():
    scan_type = input("Do you want to scan (1) Single IP or (2) IP Range? (Enter 1 or 2): ")

    if scan_type == "1":
        target_ip = input("Enter the target IP address (e.g., 192.168.1.10): ")
    elif scan_type == "2":
        target_ip = input("Enter network IP range (e.g., 192.168.1.0/24): ")
    else:
        print("Invalid choice! Exiting...")
        return

    port_range = input("Enter port range (e.g., 1-1000, 80, 443, 22-25) or press Enter for full scan: ").strip()
    if not port_range:
        port_range = "1-65535"  # Default full scan

    if scan_type == "1":
        open_ports, scan_data = scan_ports(target_ip, port_range)
        if open_ports:
            display_results(target_ip, open_ports, scan_data)
        else:
            print("\n No open ports found.")
    else:
        scan_range(target_ip, port_range)

if __name__ == "__main__":
    Metasploit_scan()
