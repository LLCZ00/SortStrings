"""
Sorts strings pulled from file (or piped in from external source)
into categories relevent to malwarea analysis.

Compatible with Windows and Linux
"""

_NAME = "sortStrings.py"
_VERS = "1.0"
_AUTHOR = "LLCZ00"

import argparse, re
import sys, os


class ArgumentHandler:
	def __init__(self):
		self.strings = ""
		self.parser = self.LLCZ00Parser(
			prog=_NAME,
			formatter_class=argparse.RawDescriptionHelpFormatter,
			epilog="Examples:\n./{0} --file=susfile\n./{0} -f susfile -l 3\nstrings susfile | ./{0}".format(_NAME),
			description=\
"""Sort Executable Strings {0}, by {1}\n
Description: Sorts strings pulled from an executable file into 
categories useful for malware analysis. 
It can also sort strings pulled from another program, such as 'strings'.
""".format(_VERS, _AUTHOR)		
		)
		self.parser.add_argument(
			"-f", "--file",
			help="Path/name of file to analyze",
			dest="file",
			type=str,
			action=self.ValidateFilename,
			metavar="FILE"
		)
		self.parser.add_argument(
			"-l", "--min-length",
			help="Minimum length of strings to capture (Default=%(default)s)",
			dest="length",
			type=int,
			default=4,
			metavar="LENGTH"
		)

		self.args = self.parser.parse_args()

		# Retrieve strings from filename or from piped input
		if self.args.file:
			with open(self.args.file, "r", errors='ignore') as exe:
				self.strings = re.findall(r"[\x1f-\x7e]{{{length},}}".format(length=self.args.length), exe.read())

		elif not sys.stdin.isatty():
			self.strings = sys.stdin.readlines()

		else:
			self.parser.error(help_flag=1)

		if not self.strings:
			self.parser.error("No strings found")


	class LLCZ00Parser(argparse.ArgumentParser): # Override argparse's error method
		def error(self, message="Unknown error", help_flag=0):
			if help_flag:
				self.print_help()
			else:
				print("Error. {}".format(message))
				print("Try './{} --help' for more information.".format(self.prog))
			sys.exit(1)

	class ValidateFilename(argparse.Action): # argparse Action to ensure given file exists
		def __call__(self, parser, namespace, values, option_string=None):
			if os.path.exists(values):
				setattr(namespace, self.dest, values)
			else:
				parser.error("Filename not found '{0}'.".format(values))


##############
# Main Class #
##############

class SortStrings(ArgumentHandler):
	def __init__(self):
		super().__init__() # Handle cli arguments, has self.strings	
		self.filename = self.args.file
		self.length = self.args.length

	def sortStr(self):
		ip_matches = ["\nIP addresses\n------------"]
		url_matches = ["\nURL addresses\n-------------"]
		linuxfp_matches = ["\nLinux file paths\n----------------"]
		file_matches = ["\nPossible urls or files\n----------------------"]
		winfp_matches = ["\nWindows file paths\n------------------"]
		winvars_matches = ["\nWindows variables\n-----------------"]
		wincmd_matches = ["\nWindows commands\n----------------"]
		phrase_matches = ["\nStrings with spaces (possible phrases)\n--------------------------------------"]
		single_matches = ["\n4-8 character strings\n--------------------"]
		long_matches = ["\n8+ character strings\n--------------------"]
		compiler_matches = ["\nCompiler/C stuff\n----------------"]
		execute_matches = ["\nExecutable segments/file extensions\n----------------------------------"]
		number_matches = ["\n4-8 character numbers\n----------------------"]
		others = ["\nAll others\n----------"]

		for line in self.strings:
			if re.match(r"(?:[a-zA-Z]{3,5}://)?(?:\d{1,3}\.){3}\d{1,3}(?::[\d]{2,5})?(?:/[\w\d%-/\?=]*)?", line) != None:
				ip_matches.append(line)		

			elif re.match(r"(?:(?:[a-zA-Z]{3,5}://)?[wW]{3}\.|[a-zA-Z]{3,5}://)(?:[a-zA-Z0-9-]{2,32}\.?){1,4}(?::[\d]{2,5})?(?:/[\w\d%-/\?=]*)?", line) != None:
				url_matches.append(line)		

			elif re.match(r"(?:[\.~]{1,2})?/[\w \.\/\"-]+", line) != None:
				linuxfp_matches.append(line)		

			elif re.match(r"\w+\.[\w-]{1,3}", line) != None:
				file_matches.append(line)		

			elif re.match(r"\"?[a-zA-Z]:\\[\w \.-\\\"]*", line) != None:
				winfp_matches.append(line)		

			elif re.match(r"%[a-zA-Z0-9]{3,15}%", line) != None:
				winvars_matches.append(line)		

			elif re.match(r"(?:cmd|CMD) \/\w .*\"", line) != None:
				wincmd_matches.append(line)

			elif re.match(r"__?\S+", line) != None:
				compiler_matches.append(line)

			elif re.match(r"\.\w{3,10}", line) != None:
				execute_matches.append(line)

			elif re.match(r"\w\S*(?: \S+)+", line) != None:
				phrase_matches.append(line)

			elif re.match(r"\w\S{8,}", line) != None:
				long_matches.append(line)

			elif re.match(r"\"?[1-9]\d{3,7}\"?", line) != None:
				number_matches.append(line)

			elif re.match(r"\w\S{3,8}", line) != None:
				single_matches.append(line)

			else:
				others.append(line)

		string_list = [ip_matches, url_matches, linuxfp_matches, file_matches, winfp_matches, 
						winvars_matches, wincmd_matches, phrase_matches, single_matches, 
						long_matches, number_matches, compiler_matches, execute_matches, others]

		for lists in string_list:
			if len(lists) > 1:
				print(lists[0])
				for string in lists[1:]:
					print(string)


	def main(self):
		print("File: {0}".format(self.filename))
		print("Minimum length: {}".format(self.length))
		self.sortStr()

if __name__ == "__main__":
	sort = SortStrings()
	sort.main()
