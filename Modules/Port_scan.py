import scapy.all as scapy
import nmap

def scan_network(ip_range):
    """ Scans the network for live hosts """
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for element in answered_list:
        devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})

    return devices

def scan_ports(ip, port_range="1-65535"):
    """ Scans open ports and retrieves service details """
    nm = nmap.PortScanner()
    nm.scan(ip, port_range, arguments='-sV')  # -sV enables version detection
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

    return open_ports

def Port_scan():
    scan_type = input("Do you want to scan a (1) Single IP or (2) Network range? (Enter 1 or 2): ")

    if scan_type == "1":
        target_ip = input("Enter the target IP address (e.g., 192.168.1.10): ")
        targets = [{"ip": target_ip}]
    elif scan_type == "2":
        network = input("Enter network IP range (e.g., 192.168.1.0/24): ")
        print("\nScanning Network...")
        targets = scan_network(network)
        for device in targets:
            print(f"Found Device: IP: {device['ip']}, MAC: {device.get('mac', 'Unknown')}")
    else:
        print("Invalid choice! Exiting...")
        return

    port_range = input("Enter port range (e.g., 1-1000, 80, 443, 22-25) or press Enter for full scan: ").strip()
    if not port_range:
        port_range = "1-65535"

    for target in targets:
        ip = target['ip']
        print(f"\nScanning open ports on {ip} within range {port_range}...")
        open_ports = scan_ports(ip, port_range)

        if open_ports:
            print("\nOpen Ports & Services:")
            for port, details in open_ports.items():
                print(f"Port {port}: {details['service']} - {details['details']}")
        else:
            print("No open ports found.")

if __name__ == "__main__":
    Port_scan()