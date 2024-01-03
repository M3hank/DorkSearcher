import os
import re
import argparse
from concurrent.futures import ThreadPoolExecutor

def highlight_dork_in_line(line, dorks):
    for dork in dorks:
        red_start = "\033[91m"
        red_end = "\033[0m"
        highlighted_dork = f"{red_start}{dork}{red_end}"
        line = re.sub(dork, highlighted_dork, line, flags=re.IGNORECASE)
    return line

def search_file(file_path, dorks, file_types=None, exact_word=False, context=None):
    # Check file extension if file_types is specified
    if file_types is not None:
        _, file_extension = os.path.splitext(file_path)
        if file_extension.lower() not in file_types:
            return  # Skip the file if its extension is not in the list

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            line_number = 0
            for line in file:
                line_number += 1
                for dork in dorks:
                    if exact_word:
                        pattern = r'\b' + re.escape(dork) + r'\b'
                    else:
                        pattern = re.escape(dork)
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        start, end = match.start(), match.end()
                        if context is None:
                            context = 50  # Default context of around 50 characters
                        context_start = max(start - context, 0)
                        context_end = min(end + context, len(line))
                        context_text = line[context_start:context_end]
                        highlighted_line = highlight_dork_in_line(context_text.strip(), dorks)
                        cyan_start = "\033[96m"
                        yellow_start = "\033[93m"
                        color_end = "\033[0m"
                        print(f"{cyan_start}Found in {file_path}{color_end}, {yellow_start}Line {line_number}:{color_end} {highlighted_line}")
                        break
    except UnicodeDecodeError:
        # Ignore binary or non-UTF-8 encoded files
        pass
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"Error processing file {file_path}: {e}")

def traverse_repo(repo_path, dorks, max_threads, file_types=None, exact_word=False, context=None):
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for root, dirs, files in os.walk(repo_path):
            for file in files:
                file_path = os.path.join(root, file)
                executor.submit(search_file, file_path, dorks, file_types, exact_word, context)

def main():
    parser = argparse.ArgumentParser(description="Search for specified 'dorks' in files within a directory and its subdirectories.")
    parser.add_argument("directory_path", metavar="directory_path", type=str, help="Path to the directory to start the operation")
    parser.add_argument("--dorks", metavar="dorks", nargs='+', required=True, help="List of search terms (dorks) to find in the files")
    parser.add_argument("--max-threads", metavar="max_threads", type=int, default=10, help="Maximum number of threads")
    parser.add_argument("-ft", "--file-types", metavar="file_types", nargs='+', help="List of file extensions to include in the search (e.g., .py .php .txt)")
    parser.add_argument("-mw", "--exact-word", action="store_true", help="Match the exact word only")
    parser.add_argument("-c", "--context", metavar="context", type=int, default=50, help="Number of characters around the dork to print")

    args = parser.parse_args()

    # Convert file types to lower case and prepend '.' if missing
    file_types = ['.' + ft.lower() if not ft.startswith('.') else ft.lower() for ft in args.file_types] if args.file_types else None

    traverse_repo(args.directory_path, args.dorks, args.max_threads, file_types, args.exact_word, args.context)

if __name__ == "__main__":
    main()
