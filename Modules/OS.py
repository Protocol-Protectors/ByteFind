import subprocess
import re
def detect_os(ip):
    try:
        result = subprocess.run(["ping", "-n", "1", ip], capture_output=True, text=True)
        ttl_match = re.search(r"TTL=(\d+)", result.stdout, re.IGNORECASE)

        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl > 100:
                os_guess = "Windows"
            elif ttl <= 100:
                os_guess = "Linux/Unix"
            else:
                os_guess = "Unknown OS"

            return f"IP: {ip} | Detected OS: {os_guess} | TTL: {ttl}"
        else:
            return f"Could not determine OS for {ip}. No TTL value found."
    except Exception as e:
        return f"Error detecting OS for {ip}: {e}"

def OS(target_ip):
   ip_to_check = target_ip #input("Enter IP address: ")
   print(detect_os(ip_to_check))
if __name__ == "__main__":
    OS()