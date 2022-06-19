# String Sorting
### stringSort.py
Sorts strings pulled from an executable file into categories useful for malware analysis.<br/>
Works with both Linux and Windows.
## Usage
```
Project Name 

Usage: ./xbuild.sh [options] TARGET

Required:
  TARGET                            Architecture to build CC for

Options:
  -h, --help                        Show usage (this page)


Examples:
xbuild.sh i386
```
## Additional Details
stringSort.py uses regular expressions to sort an executables strings into the following categories:
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
- Piping input in results in a whacky extra space between each line, for some reason
