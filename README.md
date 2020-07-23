# httpscanner
Perform mass scans of domains to discover poorly configured HTTP servers

## Todo:
- Turn each analysis thread into a crawler that fully maps out and analyses each page of the designated site
	- Save a full list of files and folders found by the crawler
		- Create a visual map to help understand the site architecture
		- Create a seperate folder and log file for each site
- Add -i option to only analyse the index page
- Add -s option to save everything crawled from the site
- Add analysis function to scan for potentially vulnerable inputs