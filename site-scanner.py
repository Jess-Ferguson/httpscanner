#!/usr/bin/python3

import argparse

from HTTPScanner.scanner import HTTPScanner
from HTTPScanner.builtin_functions import analysis, tests


def initialiseParser():
    parser = argparse.ArgumentParser(description = "Perform bulk analysis of HTTP web servers")

    parser.add_argument("--threads", "-d", help = "specify the number of threads to use (minimum 2)", type = int)
    parser.add_argument("--retries", "-r", help = "specify the number of retry attempts for requests that time out", type = int)
    parser.add_argument("--timeout", "-t", help = "specify the maximum time to wait for a site to respond", type = int)
    parser.add_argument("--files", "-f", nargs = "+", help = "specify the input file name(s)", type = str, required = True)

    return parser


def main():
    parser = initialiseParser()
    args = parser.parse_args()

    scanner = HTTPScanner(args.files, analysis, tests)

    if args.threads:
        scanner.threads(args.threads)

    if args.timeout:
        scanner.timeout(args.timeout)

    if args.retries:
        scanner.retries(args.retries)

    scanner.scan()


if __name__ == "__main__":
    main()
