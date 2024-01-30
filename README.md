
# DorkSearcher

DorkSearcher is a Python tool for searching specific terms (dorks) in files within a specified directory and its subdirectories. It highlights occurrences of these terms and provides context around them. This tool is especially useful for code reviews, security audits, or general text searches where specific patterns or keywords are of interest.

## Features

- **Search Specific Terms**: Search for user-defined terms (dorks) in text files.
- **Directory Traversal**: Recursively search through all files in a specified directory and its subdirectories.
- **File Type Filtering**: Limit the search to specific file types.
- **Context Display**: Show the surrounding context of each found term for better understanding.
- **Case Sensitivity Option**: Choose between case-sensitive or case-insensitive searches.
- **Exact Word Matching**: Option to match only the exact word.
- **Multi-threading Support**: Utilize multiple threads for faster search operations.
- **Dork File Support**: Load dorks from a file, enabling the use of a large number of search terms.

## Installation

DorkSearcher requires Python 3. Install the tool by cloning this repository:

```bash
git clone <repository-url>
cd DorkSearcher
```

## Usage

To use DorkSearcher, navigate to the directory containing the tool and run:

```bash
python dorksearcher.py <directory_path> --dorks <dorks> [options]
```

### Arguments

- `directory_path`: Path to the directory to start the search operation.
- `--dorks`: List of search terms (dorks) to find in the files (space-separated).
- `--dork-file`: Path to a text file containing a list of dorks.

### Options

- `--max-threads`: Maximum number of threads for searching (default: 10).
- `-ft, --file-types`: List of file extensions to include in the search (e.g., .py, .php, .txt).
- `-mw, --exact-word`: Match the exact word only.
- `-c, --context`: Number of characters around the dork to print (default: 50).
- `-cs, --case-sensitive`: Enable case-sensitive search.

## Example

```bash
python dorksearcher.py /path/to/directory --dorks password secret --file-types .py .txt --context 30
```

This command searches for the words 'password' and 'secret' in `.py` and `.txt` files within `/path/to/directory`, showing 30 characters of context around each occurrence.

## License

This project is licensed under the MIT License - see the LICENSE.md file for details.
