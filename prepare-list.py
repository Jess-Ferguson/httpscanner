#!/usr/bin/python3
# Script to take a hosts file and convert it to a format that the scanner script can use

import sys
import os

def main():
	if len(sys.argv) <= 1:
		print("Usage: %s [input file(s)]" % (sys.argv[0]))
	else:
		files = [file for file in sys.argv if file != sys.argv[0]]

		for filename in files:
			if "-prepared" in filename:
				continue

			output_filename, output_file_extension = os.path.splitext(filename)
			output_filename = output_filename + "-prepared" + output_file_extension

			input_handle = open(filename, "r")
			output_handle = open(output_filename, "w")

			print("Preparing file \"%s\"..." % filename)

			for line in input_handle:
				if line[0] != '#':
					output_line = line.split("127.0.0.1\t", 1)
					if len(output_line) > 1:
						output_handle.write(output_line[1])

			input_handle.close()
			print("Done!\n")
 

if __name__=="__main__":
	main()