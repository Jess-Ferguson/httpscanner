# httpscanner.py - Multithreaded bulk domain scanner to detect poorly configured http servers

import logging
import os
import queue
import requests
import threading

from requests import Timeout, HTTPError


class HTTPScannerException(Exception):
    """ Base class for exceptions related to HTTPScanner internals """
    pass


class InvalidTimeoutError(HTTPScannerException):
    """ Raised when the timeout value is invalid """
    pass


class InvalidRetriesError(HTTPScannerException):
    """ Raised when the number of retries is invalid """
    pass


class InvalidNumOfThreadsError(HTTPScannerException):
    """ Raised when the number of threads given is invalid """
    pass


class HTTPScanner:
    def __init__(self, input_file_list, analysis_functions, timeout=5, retries=3, num_of_threads=50, separator='\t'):
        if timeout <= 0:
            raise InvalidTimeoutError

        if retries < 0:
            raise InvalidRetriesError

        if num_of_threads < 2:
            raise InvalidNumOfThreadsError

        self._input_file_list = input_file_list
        self._analysis_functions = analysis_functions
        self._timeout = timeout
        self._retries = retries
        self._num_of_threads = num_of_threads
        self.separator = separator
        logging.basicConfig(level=logging.INFO, format="[%(asctime)-15s]\t[%(levelname)s]\t%(message)s")

    def timeout(self, timeout):
        if timeout <= 0:
            raise InvalidTimeoutError

        self._timeout = timeout

    def retries(self, retries):
        if retries < 0:
            raise InvalidRetriesError
        
        self._retries = retries

    def threads(self, num_of_threads):
        if num_of_threads < 2:
            raise InvalidNumOfThreadsError
        
        if num_of_threads > 50:
            logging.warning("Using more than 50 threads is not recommended and may cause connections to reset")
        
        self._num_of_threads = num_of_threads

    def analysis_functions(self, analysis_functions):
        self._analysis_functions = analysis_functions

    def _analyse_sites(self, input_queue, output_queue, header):
        while True:
            current_site_url = input_queue.get()

            if current_site_url is None:
                return

            if "http://" not in current_site_url:
                current_site_url = f"http://{current_site_url}"

            if current_site_url[-1] == '\n':
                current_site_url = current_site_url[:-1]

            logging.info("[%s] Trying site...", current_site_url)

            site_analysis_string = f"[{current_site_url}]"
            session = requests.Session()
            session.headers.update(header)

            for n in range(self._retries):
                try:
                    response = session.get(current_site_url, timeout=self._timeout)
                except HTTPError as http_error:
                    logging.warning("[%s] Could not connect: %s", current_site_url, http_error.code)
                    site_analysis_string += f"{self.separator}Inaccessible ({str(http_error.code)})"
                except Timeout:
                    if n + 1 != self._retries:
                        logging.info("[%s] Timed out, retrying... (%d of %d)!", current_site_url, n + 1, self._retries)
                        continue

                    logging.warning("[%s] Final retry failed! (%d of %d)", current_site_url, n + 1, self._retries)
                except Exception as exception:
                    logging.warning("[%s] Could not connect: %s", current_site_url, exception)
                    site_analysis_string += f"{self.separator}Inaccessible"
                else:
                    site_analysis_string += f"{self.separator}Live"

                    for func_name in self._analysis_functions:
                        site_analysis_string += self.separator

                        try:
                            site_analysis_string += self._analysis_functions[func_name](current_site_url, response.text, response.headers)
                        except Exception as exception:
                            logging.error("Caught exception in analysis function \"%s\": %s", func_name, exception)

                    logging.info("[%s] Successfully analysed site!", current_site_url)

                break

            output_queue.put(site_analysis_string)

    def _file_output(self, output_queue, output_file_handle):
        while True:
            analysed_site = output_queue.get()

            if analysed_site == None:
                break

            output_file_handle.write(analysed_site + '\n')
            # Constantly flushing the file handle is very slow
            # TODO: Add a verbose option to HTTPScanner to flush the output file handle only when specified by the user 
            output_file_handle.flush()

    def scan(self):
        header = { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0" }  # Add options to randomise/specify
        threads = []

        for input_file_name in self._input_file_list:
            output_file_name = f"{os.path.splitext(input_file_name)[0]}-sites-analysed.txt"

            try:
                input_file_handle = open(input_file_name, "r", encoding="ISO-8859-1")
            except IOError:
                logging.error("Could not open input file %s, skipping!" % input_file_name)
                continue

            try:
                output_file_handle = open(output_file_name, "w")
            except IOError:
                logging.error("Error: Could not open output file %s, skipping!" % output_file_name)
                input_file_handle.close()
                continue

            input_queue = queue.Queue(0)
            output_queue = queue.Queue(0)

            # Load the site list into a thread-safe queue to avoid race conditions in file reads
            for line in input_file_handle:
                input_queue.put(line)

            # Initialise thread zero, which is used for handling the output queue and writing the results to a file
            thread = threading.Thread(
                target=self._file_output,
                args=(
                    output_queue,
                    output_file_handle
                )
            )
            threads.append(thread)
            thread.start()

            # Initialise (_num_of_threads - 1) threads for site analysis
            for thread_index in range(self._num_of_threads - 1):
                thread = threading.Thread(
                    target=self._analyse_sites,
                    args=(
                        input_queue,
                        output_queue,
                        header
                    )
                )
                threads.append(thread)
                thread.start()

            input_file_handle.close()

            for i in range(1, self._num_of_threads):
                input_queue.put(None)

            # No, you cannot join these two loops...

            for i in range(1, self._num_of_threads):
                threads[i].join()

            output_queue.put(None)
            threads[0].join()

            # Clear the thread list so there are no problems on the next file
            threads = [None] * self._num_of_threads

            output_file_handle.close()
