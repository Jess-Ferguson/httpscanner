# analysis.py - File containing the default analysis functions for the httpscanner module

def sigDetection(site_name, page_contents, header):
    file_extensions = [
        ".tar.gz",
        ".zip",
        ".7z",
        ".rar",
        ".exe",
        ".sql",
        ".db",
        ".bin"
    ]

    key_words = [
        "backup",
        "hidden",
        "admin",
        "login",
        "database",
        "leak",
        "scam",
        "temp"
    ]

    signatures = file_extensions + key_words
    found_sigs = ""

    for signature in signatures:
        if signature.casefold() in page_contents.casefold():
            found_sigs += signature + " "

    if found_sigs != "":
        return "Found signature(s): " + found_sigs

    return "No signatures found!"


def detectParking(site_name, page_contents, header):
    # Basic dictionary lookup to determine if site is parked
    parking_signatures = [
        "this domain is not serviced by dnsdun.com. Please contact us.",
        "Buy this domain",
        "404 Not Found",
        "parked-content.godaddy.com",
        "Sponsored Listings",
        "Parkingcrew",
        "Freenom",
        "This is the default welcome page used to test the correct operation of the Apache2 server",
        "Sorry, this page doesn\"t exist.",
        "WEBSITE DELETED",
        "Website is sleeping",
        "PHPMyAdmin installation",
        "Account Suspended",
        "You have successfully installed the OpenLiteSpeed Web Server!",
        "under construction",
        "Website is Under Maintenance",
        "buydomains.com",
        "Page cannot be displayed",
        "This site is temporarily unavailable.",
        "Error. Page cannot be displayed.",
        "Website is no longer available"
    ]

    for signature in parking_signatures:
        if signature in page_contents:
            return "Parked"

    return "Not parked"

# This test is very basic and only tests for non-English characters
# TODO: Create a more comprehensive test
def is_english(site_name, page_contents, header):
    try:
        page_contents.encode(encoding="utf-8").decode("ascii")
    except UnicodeDecodeError:
        return "Non-English characters detected"

    return "Only English characters detected"


def detectIndexing(site_name, page_contents, header):
    minimum_page_sizes = {
        "Apache": 15,
        "nginx": 15,
        "LiteSpeed": 10
    }

    if "Index of " not in page_contents:
        return "Not indexed"

    page_size = page_contents.count("\n")
    server_type = header["Server"] if "Server" in header else ""

    for server in minimum_page_sizes:
        # For checking the size of the page. Trust the page more than what it says in the header.
        if (server in page_contents) or (server in server_type):
            server_type = server_type
            if page_size < minimum_page_sizes[server]:
                return "Not indexed"
            elif page_size < minimum_page_sizes[server] + 1 and "cgi-bin" in page_contents:
                return "Not indexed"
            break

    if page_size < 10:
        return "Not indexed"

    return "Indexed"


# TODO: Add better logic for detecting empty sites, i.e. minimal html tags
def is_empty(site_name, page_contents, header):
    return "Not empty" if page_contents else "Empty"


def stripHeaders(site_name, page_contents, header):
    headerString = ""

    for key, value in header.items():
        headerString += f"{key}: {header[key]}, "

    return f"Header: {headerString[:-2]}" if headerString else "No header"


builtinAnalysis = {
    "detectParking": detectParking,
    "detectIndexing": detectIndexing,
    "sigDetection": sigDetection,
    "is_empty": is_empty,
    "is_english": is_english,
    "stripHeaders": stripHeaders,
}
