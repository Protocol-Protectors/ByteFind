import re
import webbrowser
import urllib.parse
import os

def validate_and_format_url(domain):
    """Validate and format domain to a proper URL if needed."""
    if not domain:
        return None

    # Check if it's already a URL (starts with http:// or https://)
    if not re.match(r'^https?://', domain):
        # If not a URL, add https:// prefix
        domain = f"https://{domain}"

    # Basic URL validation
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+'  # domain name
        r'[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?'  # TLD
        r'(/.*)?$'  # optional path
    )

    if url_pattern.match(domain):
        return domain
    else:
        return None

def extract_domain(url):
    """Extract domain from URL without protocol and path."""
    if not url:
        return ""

    # Remove protocol (http:// or https://)
    domain = re.sub(r'^https?://', '', url)

    # Remove path if any
    domain = domain.split('/', 1)[0]

    return domain

def build_google_dork_url(query):
    """Build a Google search URL with the dork query."""
    base_url = "https://www.google.com/search?q="
    encoded_query = urllib.parse.quote(query)
    return base_url + encoded_query

def read_dorks_from_file(filename, domain=None):
    """Read dork queries from a file and format them with the given domain."""
    dorks = {}
    try:
        if not os.path.exists(filename):
            return dorks

        with open(filename, 'r') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Split by first colon to separate name and query
                    if ':' in line:
                        dork_name, dork_query = line.split(':', 1)
                        dork_name = dork_name.strip()
                        dork_query = dork_query.strip()
                    else:
                        dork_name = f"Custom {len(dorks) + 1}"
                        dork_query = line

                    # Only replace domain if one is provided
                    if domain:
                        # Replace {domain} placeholder with actual domain if present
                        dork_query = dork_query.replace('{domain}', domain)

                        # Ensure the query has the site: operator if not already present
                        if "site:" not in dork_query:
                            dork_query = f"site:{domain} {dork_query}"

                    dorks[dork_name] = dork_query
    except Exception as e:
        print(f"\nError reading file: {e}")
    return dorks

def write_dork_to_file(filename, dork_name, dork_query):
    """Write a new dork to the file."""
    try:
        # Create file if it doesn't exist
        if not os.path.exists(filename):
            with open(filename, 'w') as file:
                file.write("# Google Dork queries\n")
                file.write("# Format: Dork Name: Dork Query\n")
                file.write("# Use {domain} as a placeholder for the domain\n\n")

        # Append the new dork
        with open(filename, 'a') as file:
            file.write(f"{dork_name}: {dork_query}\n")

        return True
    except Exception as e:
        print(f"\nError writing to file: {e}")
        return False

def is_dork_already_exists(dorks, new_dork_query):
    """Check if a similar dork already exists."""

    # Normalize the query for comparison by removing site: part and whitespace
    def normalize_query(query):
        # Remove site:domain part if present
        normalized = re.sub(r'site:\S+\s*', '', query)
        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        return normalized.lower()

    new_normalized = normalize_query(new_dork_query)

    for dork_query in dorks.values():
        if normalize_query(dork_query) == new_normalized:
            return True

    return False

def google_dork():
    while True:
        domain_input = input("Enter a domain or URL (e.g., example.com or https://example.com): ").strip()

        if not domain_input:
            print("No input provided. Exiting...")
            break

        valid_url = validate_and_format_url(domain_input)

        if valid_url:
            domain = extract_domain(valid_url)

            while True:
                print("\nOptions:")
                print("1. Show all default dorks")
                print("2. Enter custom dork")

                choice = input("\nSelect an option (1-2): ").strip()

                if choice == "1":
                    # Ask for dorks file
                    dorks_file = input("Enter path to dorks file (default_filename:dorks.txt): ").strip()
                    if not dorks_file:
                        print("No file specified. Going back to menu.")
                        continue

                    # Read dorks from file
                    dorks = read_dorks_from_file(dorks_file, domain)

                    if not dorks:
                        print("No dorks available. Please check the dorks file.")
                        continue

                    print("\nAvailable Dorks:")

                    # Display all available dorks with their queries
                    for i, (dork_name, dork_query) in enumerate(dorks.items(), 1):
                        print(f"{i}. {dork_name}")
                        print(f"   Query: {dork_query}")
                        search_url = build_google_dork_url(dork_query)
                        print(f"   URL: {search_url}")
                        print()  # Empty line for readability

                    # Ask if user wants to open any of these in browser
                    open_option = input(
                        "\nOpen dork in browser? Enter number or 'A' for all (or any other key to skip): ").strip().upper()

                    if open_option == 'A':
                        print("\nOpening all dorks in browser...")
                        for dork_name, dork_query in dorks.items():
                            print(f"Opening: {dork_name}")
                            webbrowser.open(build_google_dork_url(dork_query))
                    elif open_option.isdigit() and 1 <= int(open_option) <= len(dorks):
                        dork_name = list(dorks.keys())[int(open_option) - 1]
                        dork_query = dorks[dork_name]
                        print(f"\nOpening: {dork_name}")
                        webbrowser.open(build_google_dork_url(dork_query))

                elif choice == "2":
                    # Ask for dorks file to add to
                    dorks_file = input("Enter path to dorks file to add to (default_filename:dorks.txt): ").strip()
                    if not dorks_file:
                        print("No file specified. Going back to menu.")
                        continue

                    # Read existing dorks to check for duplicates (without domain replacement)
                    existing_dorks = read_dorks_from_file(dorks_file)

                    # Custom dork options
                    print("\nCustom Dork Building:")
                    print("Format: Dork Name: Dork Query")
                    print("Use {domain} as a placeholder for the domain")
                    print("Example: Directory Listing: site:{domain} intitle:index.of")
                    # Get dork name
                    print("\nExample:  Dork Name: Database Files ")
                    dork_name = input("Enter a name for your dork: ").strip()
                    if not dork_name:
                        dork_name = f"Custom Dork {len(existing_dorks) + 1}"

                    # Get dork query
                    print("\nExample:  Dork Query: site:{domain} ext:sql OR ext:dbf OR ext:mdb OR ext:db ")
                    custom_dork = input("Enter your custom dork query: ").strip()
                    if not custom_dork:
                        print("No query provided. Going back to menu.")
                        continue

                    # Check if the query already includes the site: operator
                    if "site:" not in custom_dork:
                        # Use {domain} placeholder in the saved query
                        generic_dork = f"site:{{domain}} {custom_dork}"
                        # Create a domain-specific version for immediate use
                        domain_specific_dork = f"site:{domain} {custom_dork}"
                    else:
                        # If query already has site:something, store as is but warn user
                        generic_dork = custom_dork
                        domain_specific_dork = custom_dork.replace("{domain}", domain)
                        print("\nWarning: Your query already contains a 'site:' operator.")
                        print("Consider using {domain} as a placeholder for reusability.")

                    # Check if similar dork already exists
                    if is_dork_already_exists(existing_dorks, generic_dork):
                        print("\nA similar dork already exists in the file!")
                        add_anyway = input("Add anyway? (y/n): ").strip().lower()
                        if add_anyway != 'y':
                            print("Dork not added. Going back to menu.")
                            continue

                    # Save the dork to file
                    if write_dork_to_file(dorks_file, dork_name, generic_dork):
                        print(f"\nDork '{dork_name}' saved to {dorks_file}")

                        # Ask if user wants to execute the dork now
                        execute_now = input("\nExecute this dork now? (y/n): ").strip().lower()
                        if execute_now == 'y':
                            print(f"\nExecuting: {dork_name}")
                            print(f"Query: {domain_specific_dork}")
                            search_url = build_google_dork_url(domain_specific_dork)
                            print(f"Opening browser with search URL: {search_url}")
                            webbrowser.open(search_url)
                    else:
                        print("\nFailed to save dork to file.")

                else:
                    print("Invalid choice. Please try again.")
        else:
            print("Invalid domain or URL format. Please try again.")

if __name__ == "__main__":
    google_dork()