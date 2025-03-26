import re
import whois
import dns.resolver
import dns.reversename

def validate_domain(domain):
    """ Validates if the input is a proper domain or URL """
    domain_regex = r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    return re.match(domain_regex, domain) is not None

def extract_domain(url):
    """ Extracts the domain from a URL if provided """
    url = url.strip().lower()
    url = url.replace("http://", "").replace("https://", "").split('/')[0]
    return url

def get_dns_records(domain):
    """ Retrieves all common DNS records using dnspython library """
    dns_info = {}

    # A Records (IPv4 address)
    try:
        dns_info['A'] = [answer.address for answer in dns.resolver.resolve(domain, 'A')]
    except dns.resolver.NoAnswer:
        dns_info['A'] = "No record found"
    except Exception as e:
        dns_info['A'] = f"Error fetching A records: {str(e)}"

    # AAAA Records (IPv6 address)
    try:
        dns_info['AAAA'] = [answer.address for answer in dns.resolver.resolve(domain, 'AAAA')]
    except dns.resolver.NoAnswer:
        dns_info['AAAA'] = "No record found"
    except Exception as e:
        dns_info['AAAA'] = f"Error fetching AAAA records: {str(e)}"

    # MX Records (Mail Exchange)
    try:
        dns_info['MX'] = [answer.exchange.to_text() for answer in dns.resolver.resolve(domain, 'MX')]
    except dns.resolver.NoAnswer:
        dns_info['MX'] = "No record found"
    except Exception as e:
        dns_info['MX'] = f"Error fetching MX records: {str(e)}"

    # NS Records (Name Servers)
    try:
        dns_info['NS'] = [answer.to_text() for answer in dns.resolver.resolve(domain, 'NS')]
    except dns.resolver.NoAnswer:
        dns_info['NS'] = "No record found"
    except Exception as e:
        dns_info['NS'] = f"Error fetching NS records: {str(e)}"

    # CNAME Records (Canonical Name)
    try:
        dns_info['CNAME'] = [answer.to_text() for answer in dns.resolver.resolve(domain, 'CNAME')]
    except dns.resolver.NoAnswer:
        dns_info['CNAME'] = "No record found"
    except Exception as e:
        dns_info['CNAME'] = f"Error fetching CNAME records: {str(e)}"

    # TXT Records (Text)
    try:
        dns_info['TXT'] = [answer.to_text() for answer in dns.resolver.resolve(domain, 'TXT')]
    except dns.resolver.NoAnswer:
        dns_info['TXT'] = "No record found"
    except Exception as e:
        dns_info['TXT'] = f"Error fetching TXT records: {str(e)}"

    # SOA Records (Start of Authority)
    try:
        dns_info['SOA'] = [answer.to_text() for answer in dns.resolver.resolve(domain, 'SOA')]
    except dns.resolver.NoAnswer:
        dns_info['SOA'] = "No record found"
    except Exception as e:
        dns_info['SOA'] = f"Error fetching SOA records: {str(e)}"

    # PTR Records (Reverse DNS)
    try:
        ip = dns.resolver.resolve(domain, 'A')[0].address  # Get first A record IP
        ptr_query = dns.reversename.from_address(ip)
        dns_info['PTR'] = [answer.to_text() for answer in dns.resolver.resolve(ptr_query, 'PTR')]
    except (dns.resolver.NoAnswer, IndexError):
        dns_info['PTR'] = "No record found or no A record to reverse"
    except Exception as e:
        dns_info['PTR'] = f"Error fetching PTR records: {str(e)}"

    # SRV Records (Service Locator)
    try:
        dns_info['SRV'] = [answer.to_text() for answer in dns.resolver.resolve(domain, 'SRV')]
    except dns.resolver.NoAnswer:
        dns_info['SRV'] = "No record found"
    except Exception as e:
        dns_info['SRV'] = f"Error fetching SRV records: {str(e)}"

    # CAA Records (Certification Authority Authorization)
    try:
        dns_info['CAA'] = [answer.to_text() for answer in dns.resolver.resolve(domain, 'CAA')]
    except dns.resolver.NoAnswer:
        dns_info['CAA'] = "No record found"
    except Exception as e:
        dns_info['CAA'] = f"Error fetching CAA records: {str(e)}"

    return dns_info

def get_whois_info(domain):
    """ Retrieves WHOIS information for the domain """
    try:
        whois_info = whois.whois(domain)
        return whois_info
    except Exception as e:
        return f"WHOIS lookup failed: {str(e)}"

def dns_whois_module():
    """ Main function for DNS and WHOIS lookup """
    user_input = input("Enter a domain or URL (e.g., example.com or https://example.com): ")
    domain = extract_domain(user_input)

    if not validate_domain(domain):
        print("Invalid domain! Please enter a valid domain name.")
        return

    print("\nFetching DNS Records...")
    dns_records = get_dns_records(domain)
    for record_type, values in dns_records.items():
        print(f"{record_type} Records: {values}")

    print("\nFetching WHOIS Information...")
    whois_info = get_whois_info(domain)
    print(whois_info)

if __name__ == "__main__":
    dns_whois_module()