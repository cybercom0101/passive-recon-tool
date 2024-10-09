import whois
import dns.resolver
import ssl
import socket
import asyncio
import aiohttp
import re
import requests
from urllib.parse import urlparse

# Cache for storing previously fetched results (optional for performance)
cache = {}

# Async Function for making requests
async def async_fetch(url, session):
    try:
        async with session.get(url) as response:
            return await response.text()
    except Exception as e:
        return f"Error fetching data: {e}"

# WHOIS Lookup
async def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return f"Error during WHOIS lookup: {e}"

# DNS Enumeration (Batch queries)
async def dns_lookup(domain):
    if domain in cache:
        return cache[domain]
    records = {}
    try:
        # Query A records first
        answers = dns.resolver.resolve(domain, 'A')
        records['A'] = [str(answer) for answer in answers] if answers else "No A records found."

        # Batch additional DNS record types
        record_types = ['NS', 'MX', 'TXT', 'CAA', 'SOA']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(answer) for answer in answers] if answers else f"No {record_type} records found."
            except dns.resolver.NoAnswer:
                records[record_type] = f"No {record_type} records found."
            except Exception as e:
                records[record_type] = f"Error fetching {record_type}: {e}"

    except dns.resolver.NoAnswer:
        records['Error'] = "No answer found for DNS query."
    except Exception as e:
        records['Error'] = str(e)
    
    cache[domain] = records
    return records

# Subdomain Enumeration using crt.sh
async def subdomain_enum(domain, session):
    subdomains = []
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    try:
        response = await async_fetch(url, session)
        if isinstance(response, str) and "Error" in response:
            return response
        response_json = re.findall(r'{.*?}', response)  # Match JSON-like structures in response
        for entry in response_json:
            subdomain_data = re.findall(r'"name_value":"(.*?)"', entry)
            if subdomain_data:
                for subdomain in subdomain_data:
                    if subdomain not in subdomains:
                        subdomains.append(subdomain)
    except Exception as e:
        return f"Error fetching subdomains: {e}"
    return subdomains

# SSL Certificate Information
async def ssl_certificate_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        return cert
    except Exception as e:
        return f"Error fetching SSL certificate: {e}"

# Google Dorking
def google_dork(domain):
    dorks = [
        f'site:{domain} ext:pdf',
        f'site:{domain} intitle:"index of"',
        f'site:{domain} "confidential"',
        f'site:{domain} inurl:admin',
        f'site:{domain} inurl:login'
    ]
    results = {}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }

    for dork in dorks:
        query = f"https://www.google.com/search?q={dork}"
        try:
            response = requests.get(query, headers=headers)
            if response.status_code == 200:
                links = re.findall(r'<a href="(https?://[^\"]+)', response.text)
                results[dork] = links
            else:
                results[dork] = f"Failed to fetch dork results: Status code {response.status_code}"
        except Exception as e:
            results[dork] = f"Error during Google dorking: {e}"
    return results

# Public Archive Queries (Wayback Machine)
async def wayback_machine(domain, session):
    url = f'https://archive.org/wayback/available?url={domain}'
    return await async_fetch(url, session)

# Reverse DNS Lookup
def reverse_dns(ip):
    try:
        result = socket.gethostbyaddr(ip)
        return result
    except Exception as e:
        return f"Error performing reverse DNS lookup: {e}"

# IP Geolocation
async def ip_geolocation(ip, session):
    url = f'http://ip-api.com/json/{ip}'
    return await async_fetch(url, session)

# Extract Email Addresses from Web Pages
async def extract_emails(domain, session):
    url = f"http://{domain}"
    try:
        async with session.get(url) as response:
            html_content = await response.text()
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html_content)
            return list(set(emails)) if emails else "No emails found."
    except Exception as e:
        return f"Error fetching emails: {e}"

# Open Ports Scanning (using socket)
async def port_scanning(domain):
    open_ports = []
    ports = [21, 22, 23, 25, 53, 80, 443, 8080]  # Common Ports
    tasks = []
    for port in ports:
        tasks.append(scan_port(domain, port))
    
    results = await asyncio.gather(*tasks)
    for port, result in zip(ports, results):
        if result:
            open_ports.append(port)
    return open_ports

async def scan_port(domain, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((domain, port))
        sock.close()
        return result == 0
    except Exception as e:
        return False

# Check HTTP Headers
async def check_http_headers(domain, session):
    url = f"http://{domain}"
    try:
        async with session.get(url) as response:
            headers = dict(response.headers)
            return headers
    except Exception as e:
        return f"Error fetching HTTP headers: {e}"

# Metadata Extraction from Public Files
async def extract_metadata(domain, session):
    files = ['robots.txt', 'sitemap.xml', 'favicon.ico']
    metadata = {}
    for file in files:
        url = f"http://{domain}/{file}"
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    metadata[file] = await response.text()
        except Exception as e:
            metadata[file] = f"Error fetching {file}: {e}"
    return metadata

# Combine all functions into a passive recon tool
async def passive_recon(domain):
    print(f"\nGathering information for: {domain}\n{'-'*50}\n")

    # Create a session for reuse across all async functions
    async with aiohttp.ClientSession() as session:
        
        # WHOIS (Parallelized)
        whois_task = asyncio.create_task(whois_lookup(domain))
        
        # DNS Lookup (Parallelized)
        dns_task = asyncio.create_task(dns_lookup(domain))

        # Subdomain Enumeration (Parallelized)
        subdomain_task = asyncio.create_task(subdomain_enum(domain, session))

        # SSL Certificate Information
        ssl_task = asyncio.create_task(ssl_certificate_info(domain))

        # Wayback Machine
        wayback_task = asyncio.create_task(wayback_machine(domain, session))

        # Email Extraction
        email_task = asyncio.create_task(extract_emails(domain, session))

        # Port Scanning
        port_scan_task = asyncio.create_task(port_scanning(domain))

        # HTTP Headers Check
        http_headers_task = asyncio.create_task(check_http_headers(domain, session))

        # Metadata Extraction (e.g., robots.txt, sitemap.xml)
        metadata_task = asyncio.create_task(extract_metadata(domain, session))

        # Get WHOIS Information
        whois_info = await whois_task
        print("1. WHOIS Information:")
        if isinstance(whois_info, str):
            print(whois_info)
        else:
            for key, value in whois_info.items():
                print(f"{key}: {value}")

        print("\n" + "-"*50)

        # Get DNS Records
        dns_info = await dns_task
        print("\n2. DNS Records:")
        if 'Error' in dns_info:
            print(dns_info['Error'])
        else:
            for record_type, answers in dns_info.items():
                print(f"{record_type} Records:")
                for answer in answers:
                    print(f"  - {answer}")

        print("\n" + "-"*50)
        
        # Subdomains
        subdomains = await subdomain_task
        print("\n3. Subdomains found via Certificate Transparency:")
        if isinstance(subdomains, str):
            print(subdomains)
        else:
            for subdomain in subdomains:
                print(f"  - {subdomain}")

        print("\n" + "-"*50)

        # SSL Certificate
        ssl_info = await ssl_task
        print("\n4. SSL Certificate Information:")
        if isinstance(ssl_info, str):
            print(ssl_info)
        else:
            for key, value in ssl_info.items():
                print(f"{key}: {value}")

        print("\n" + "-"*50)

        # Google Dorking
        print("\n5. Suggested Google Dorks:")
        google_dorks = google_dork(domain)
        for dork, links in google_dorks.items():
            print(f"  - Dork: {dork}")
            if isinstance(links, list):
                for link in links:
                    print(f"    - {link}")
            else:
                print(f"    {links}")

        print("\n" + "-"*50)

        # Wayback Machine
        wayback_info = await wayback_task
        print("\n6. Wayback Machine Archive Information:")
        if isinstance(wayback_info, str):
            print(wayback_info)
        else:
            for key, value in wayback_info.items():
                print(f"{key}: {value}")

        print("\n" + "-"*50)

        # Extract Emails
        print("\n7. Extracted Email Addresses:")
        emails = await email_task
        if isinstance(emails, str):
            print(emails)
        else:
            for email in emails:
                print(f"  - {email}")

        print("\n" + "-"*50)

        # Port Scanning
        open_ports = await port_scan_task
        print("\n8. Open Ports:")
        if open_ports:
            for port in open_ports:
                print(f"  - Port {port} is open")
        else:
            print("No open ports found.")

        print("\n" + "-"*50)

        # HTTP Headers
        http_headers = await http_headers_task
        print("\n9. HTTP Headers:")
        if isinstance(http_headers, str):
            print(http_headers)
        else:
            for key, value in http_headers.items():
                print(f"{key}: {value}")

        print("\n" + "-"*50)

        # Metadata Extraction
        metadata_info = await metadata_task
        print("\n10. Metadata Information (robots.txt, sitemap.xml, etc.):")
        if isinstance(metadata_info, dict):
            for file, content in metadata_info.items():
                print(f"{file}: {content[:200]}...")  # Only show first 200 chars of the metadata

# Main function to run the tool
if __name__ == "__main__":
    domain = input("Enter domain to perform passive reconnaissance on: ")
    asyncio.run(passive_recon(domain))
