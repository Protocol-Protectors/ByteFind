import requests
import re

def is_valid_url(url):
    # Basic URL validation regex
    url_pattern = re.compile(
        r'^(https?://)?'  # Optional protocol
        r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'  # Domain name
        r'(/.*)?$'  # Optional path
    )

    # If no protocol is provided, add 'https://' for validation
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    return url_pattern.match(url)  is not None, url

def detect_waf(url):
    try:
        # Send a basic GET request
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=10)

        # Get response headers
        resp_headers = response.headers

        # Common WAF signatures in headers
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'Server: cloudflare'],
            'AWS WAF': ['x-amzn-waf-', 'Server: awselb'],
            'Sucuri': ['X-Sucuri-ID', 'Server: Sucuri/Cloudproxy'],
            'Incapsula': ['X-CDN: Incapsula', 'X-Iinfo'],
            'Akamai': ['Server: AkamaiGHost', 'X-Akamai-'],
            'F5 BIG-IP': ['X-WA-Info', 'X-Powered-By: BIG-IP'],
            'Imperva': ['X-Imforwards', 'X-CDN: Imperva'],
            'ModSecurity': ['Mod_Security', 'Server: Mod_Security'],
        }

        detected_wafs = []

        # Check headers for WAF signatures
        for waf, signatures in waf_signatures.items():
            for signature in signatures:
                if signature.lower() in (header.lower() for header in resp_headers.keys()) or \
                        any(signature.lower() in str(value).lower() for value in resp_headers.values()):
                    detected_wafs.append(waf)
                    break

        # Additional heuristic: Check for WAF-like response codes or blocks
        if response.status_code in [403, 429, 503]:
            if 'waf' in str(response.text).lower() or 'firewall' in str(response.text).lower():
                detected_wafs.append("Potential WAF (based on response behavior)")

        # Return results
        if detected_wafs:
            return {"Detected WAFs": list(set(detected_wafs))}  # Remove duplicates
        else:
            return "No WAF detected or unknown WAF in use."

    except requests.exceptions.RequestException as e:
        return f"Error: Unable to analyze the website. Details: {str(e)}"

def WAF(url):
    # Step 1: passing the URL
    user_input = url

    # Step 2: Validate the input
    is_valid, full_url = is_valid_url(user_input)
    if not is_valid:
        print(
            "Error: Invalid domain or URL format. Please enter a valid domain (e.g., example.com) or URL (e.g., https://example.com).")
        return

    # Step 3: Detect WAF
    print(f"\nAnalyzing {full_url} for WAF detection...")
    waf_result = detect_waf(full_url)

    # Print the results
    if isinstance(waf_result, dict):
        print(f"\nResults for {full_url}:")
        for key, value in waf_result.items():
            print(f"- {key}: {', '.join(value) if isinstance(value, list) else value}")
    else:
        print(waf_result)