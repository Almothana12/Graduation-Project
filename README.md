# WSTT: Web Security Testing Tool
Scans a website for common web vulnerabilities.
```
Usage:
    wstt
    wstt [options] <url>
    wstt (-h | --help)
    wstt (-v | --version)
Options:
    -c, --cookie=<cookie>          Send this Cookie with the requests
    -C, --command-injection        Scan for command injection
        --crawl                    Scan all pages in the website
    -D, --data                     Scan for sensitive data
        --fullscan                 Runs a full scan on the URL. Scans with DOM and time-based methods, and more payloads
        --gui                      Start the graphical interface
    -h, --help                     Show this screen
        --html                     Generate an HTML report
        --dom                      Scan for DOM-based XSS
        --time-based               Scan using time-based method
        --pdf                      Generate a PDF report
    -S, --sqli                     Scan for SQLi
        --time=<seconds>           The seconds to inject in time-based
        --verbose                  Show more info
    -v, --version                  Show the version of WSTT
    -V, --versions                 Scan for the server version
    -X, --xss                      Scan for XSS
```
