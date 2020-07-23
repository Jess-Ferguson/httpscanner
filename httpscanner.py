# httpscanner.py - Multithreaded bulk domain scanner to detect poorly configured http servers

import re
import sys
import os
import urllib.request
import threading
import queue
import logging

from socket import timeout
from urllib.error import HTTPError


class HttpScannerException(Exception):
    """
	Base class for httpscanner exceptions
	"""
    pass


class InvalidTimeoutError(HttpScannerException):
    """
	Raised when the timeout given is 0 or less
	"""
    pass


class InvalidRetriesError(HttpScannerException):
    """
	Raised when the number of retries is less than 0
	"""
    pass


class InvalidNumOfThreadsError(HttpScannerException):
    """
	Raised when the number of threads given is less than 2
	"""
    pass


class HttpScanner:
    def __init__(self, input_file_list, analysis_functions, timeout=5, retries=3, num_of_threads=50, separator='\t'):
        if timeout <= 0:
            raise InvalidTimeoutError
        elif retries < 0:
            raise InvalidRetriesError
        elif num_of_threads < 2:
            raise InvalidNumOfThreadsError
        else:
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
        else:
            self._timeout = timeout

        return

    def retries(self, retries):
        if retries < 0:
            raise InvalidRetriesError
        else:
            self._retries = retries

        return

    def threads(self, num_of_threads):
        if num_of_threads < 2:
            raise InvalidNumOfThreadsError
        else:
            if num_of_threads > 50:
                logging.warning("Using more than 50 threads is not recommended and may cause connections to be reset")
            self._num_of_threads = num_of_threads

        return

    def analysis_functions(self, analysis_functions):
        self._analysis_functions = analysis_functions

    def _analyse_sites(self, input_queue, output_queue, header):
        while True:
            site = input_queue.get()
            if site is None:
                return

            if "http://" not in site:
                site = "http://" + site
            if site[-1] == '\n':
                site = site[:-1]

            logging.info("[%s] Trying site...", site)

            site_category_string = '[' + site + ']'
            page = None

            for n in range(self._retries):
                try:
                    request = urllib.request.Request(site, headers=header)
                    page = urllib.request.urlopen(request, timeout=self._timeout)
                    page_contents = page.read().decode("utf-8")
                    headers = dict(page.info())
                except HTTPError as http_error:
                    logging.warning("[%s] Could not connect: %s", site, http_error.code)
                    site_category_string += self.separator + "Inaccessible (" + str(http_error.code) + ")"
                except timeout:
                    if n + 1 != self._retries:
                        logging.info("[%s] Timed out, retrying... (%d of %d)!", site, n + 1, self._retries)
                        continue
                    else:
                        logging.warning("[%s] Final retry failed! (%d of %d)", site, n + 1, self._retries)
                except Exception as exception:
                    if "Temporary failure in name resolution" in str(exception):
                        n -= 1
                        continue
                    logging.warning("[%s] Could not connect: %s", site, exception)
                    site_category_string += self.separator + "Inaccessible"
                else:
                    site_category_string += self.separator + "Live"

                    for func_name in self._analysis_functions:
                        site_category_string += self.separator
                        try:
                            site_category_string += self._analysis_functions[func_name](site, page_contents, headers)
                        except Exception as exception:
                            logging.error("Caught exception in analysis function \"%s\": %s", func_name, exception)

                    logging.info("[%s] Successfully analysed site!", site)

                break

            output_queue.put(site_category_string)

    def _file_output(self, output_queue, output_file_handle):
        while True:
            site = output_queue.get()
            if site == None:
                break
            output_file_handle.write(site + '\n')
            output_file_handle.flush()  # This is slowing us down big time, will remove when my attention span improves

    def scan(self):
        header = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'}  # Add options to randomise/specify
        threads = []

        for input_file_name in self._input_file_list:
            output_file_name = os.path.splitext(input_file_name)[0] + "-sites-analysed.txt"

            try:
                input_file_handle = open(input_file_name, "r", encoding="ISO-8859-1")
            except FileNotFoundError:
                logging.error("Could find input file %s, skipping!" % input_file_name)
                continue
            except FileIOError:
                logging.error("Could not open input file %s, skipping!" % input_file_name)
                continue

            try:
                output_file_handle = open(output_file_name, "w")
            except FileIOError:
                logging.error("Error: Could not open output file %s, skipping!" % output_file_name)
                input_file_handle.close()
                continue

            input_queue = queue.Queue(0)
            output_queue = queue.Queue(0)

            for line in input_file_handle:  # Load the site list into a thread-safe queue to avoid race conditions in file reads
                input_queue.put(line)

            thread = threading.Thread(target=self._file_output,
                                      args=(output_queue, output_file_handle))  # First thread is for file output
            threads.append(thread)
            thread.start()

            for cur_thread in range(self._num_of_threads - 1):
                thread = threading.Thread(target=self._analyse_sites, args=(
                    input_queue, output_queue, header))  # Every other thread is for analysing sites
                threads.append(thread)
                thread.start()

            input_file_handle.close()

            for i in range(1, self._num_of_threads):  # No, you cannot join these two loops...
                input_queue.put(None)

            for i in range(1, self._num_of_threads):
                threads[i].join()

            output_queue.put(None)

            threads[0].join()

            threads = [None] * self._num_of_threads  # Clear the thread list so there are no problems on the next file

            output_file_handle.close()
