# Sort File Strings
### sortStrings.py
Sorts strings pulled from an executable file into categories useful for malware analysis.<br/>
Works with both Linux and Windows.
## Usage
```
./sortStrings [-h] [-f FILE] [-l LENGTH]

Options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path/name of file to analyze
  -l LENGTH, --min-length LENGTH
                        Minimum length of strings to capture (Default=4)

Examples:
python3 ./sortStrings.py --file=susfile
sortStrings.py -f susfile -l 3
strings susfile | ./sortStrings.py

```
## Additional Details
stringSort.py pulls the strings from a file if a filename is given, or strings can be piped in directly. Strings are sorted with regular expressions into the following categories:
- IP addresses
- URLs
- Files/URLs (no http or www)
- Linux file paths
- Windows file paths
- Windows variables (%SYSTEM%)
- Windows commands (cmd /c "ping https://github.com")
- Phrases (strings with spaces)
- 4-8 character words
- 4-8 character numbers
- 8+ character words
- Compiler/C strings ( \_\_GLOBAL_HEAP_SELECTED__ )
- Executable segments (.rodata)
- "All Others" (anything unsorted)
## Issues & TODO
- Ocassionaly missorts strings, but thats just life with regular expressions
- Piping input in input from *strings* causes an extra newline between each string, due to the way *strings* handles its output
