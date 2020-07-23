import argparse
from httpscanner import *
from analysis import *


def initialiseParser():
    parser = argparse.ArgumentParser(description="Tool to bulk analyse https servers")

    parser.add_argument("--threads", "-d", help="specify the number of threads to use (minimum 2)", type=int)
    parser.add_argument("--retries", "-r", help="specify the number of retry attempts for requests that time out",
                        type=int)
    parser.add_argument("--timeout", "-t", help="specify the maximum time to wait for a site to respond", type=int)
    parser.add_argument("--files", "-f", nargs="+", help="specify the input file name(s)", type=str)

    return parser


def main():
    parser = initialiseParser()
    args = parser.parse_args()

    if args.files is not None:
        input_files = list(dict.fromkeys([file for file in args.files if file != sys.argv[0]]))
        try:
            scanner = HttpScanner(input_files, builtinAnalysis)
        except HttpScannerException as exception:
            print("Error initialising scanner: %s" % exception)
            return
    else:
        print("Error: No input files specified!")
        return

    if args.threads is not None:
        try:
            scanner.threads(args.threads)
        except InvalidNumOfThreadsError as exception:
            print("Error: Thread number cannot be less than two!")
            return

    if args.timeout is not None:
        try:
            scanner.timeout(args.timeout)
        except InvalidTimeoutError as exception:
            print("Error: Timeout cannot be less than or equal to zero!")
            return

    if args.retries is not None:
        try:
            scanner.retries(args.retries)
        except InvalidRetriesError as exception:
            print("Error: Retries cannot be less than zero!")
            return

    scanner.scan()


if __name__ == "__main__":
    main()
