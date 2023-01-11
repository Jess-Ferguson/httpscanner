# httpscanner.py - Multithreaded bulk domain scanner to detect poorly configured http servers

import logging
import os
import queue
import requests
import threading

from requests import HTTPError, Timeout, RequestException

from .exceptions import InvalidTimeoutError, InvalidRetriesError, InvalidNumOfThreadsError, AnalysisError


class HTTPScanner:
    def __init__(self, input_file_list, analysis_functions, test_functions, timeout=5, retries=3, num_of_threads=50, separator='|'):
        if timeout <= 0:
            raise InvalidTimeoutError

        if retries < 0:
            raise InvalidRetriesError

        if num_of_threads < 2:
            raise InvalidNumOfThreadsError

        self._input_file_list = input_file_list
        self._analysis_functions = analysis_functions
        self._test_functions = test_functions
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
    
    def test_functions(self, test_functions):
        self._test_functions = test_functions

    def _analyse_sites(self, input_queue, output_queue, header):
        while True:
            current_site_url = input_queue.get()

            if current_site_url is None:
                return

            if "http://" not in current_site_url:
                current_site_url = f"http://{current_site_url}"

            if current_site_url[-1] == '\n':
                current_site_url = current_site_url[:-1]

            logging.info(f"[{current_site_url}] Trying site...")

            site_analysis_string = f"[{current_site_url}]"
            session = requests.Session()
            session.headers.update(header)
            session.hooks = {
                "response": lambda r, *args, **kwargs: r.raise_for_status()
            }

            try:
                for n in range(self._retries):
                    try:
                        response = session.get(current_site_url, timeout=self._timeout)
                    except HTTPError as http_error:
                        raise AnalysisError(f"[{current_site_url}] Bad response ({http_error.response.status_code})")
                    except Timeout:
                        if n + 1 != self._retries:
                            logging.info(f"[{current_site_url}] Timed out, retrying... ({n + 1} of {self._retries})!")
                            continue

                        raise AnalysisError(f"[{current_site_url}] Final retry failed! ({n + 1} of {self._retries})")
                    except RequestException as exception:
                        raise AnalysisError(f"[{current_site_url}] Could not connect: {exception}")
                    else:
                        for test_function in self._test_functions.values():
                            test_function(current_site_url, response.text, response.headers)

                        for func_name, analysis_function in self._analysis_functions.items():
                            try:
                                site_analysis_string += f"{self.separator}{analysis_function(current_site_url, response.text, response.headers)}"
                            except Exception as exception:
                                raise AnalysisError(f"Caught unexpected exception in analysis function \"{func_name}\": {exception}")

                        logging.info(f"[{current_site_url}] Successfully analysed site!")

                    break

                output_queue.put(site_analysis_string)
            except AnalysisError as exception:
                logging.warning(str(exception))

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
        # TODO: Add option to randomise/specify User Agent and other headers
        header = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0",
            "Connection": "close" 
        }
        threads = []

        for input_file_name in self._input_file_list:
            output_file_name = f"{os.path.splitext(input_file_name)[0]}-sites-analysed.txt"

            try:
                input_file_handle = open(input_file_name, "r", encoding="ISO-8859-1")
            except IOError:
                logging.error(f"Could not open input file {input_file_name}, skipping!")
                continue

            try:
                output_file_handle = open(output_file_name, "w")
            except IOError:
                logging.error(f"Error: Could not open output file {output_file_name}, skipping!")
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
