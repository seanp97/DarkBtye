
# DarkByte

DarkByte is an advanced network reconnaissance tool that performs a series of scanning and information-gathering tasks on a given domain or IP address. It is designed for ethical hacking, penetration testing, and security analysis.

#Features

IP Information Retrieval: Fetches geolocation, ISP, and other details.

Domain Resolution: Resolves the target domain to its corresponding IP address.

Ping Test: Checks if the server is online.

Port Scanning: Scans all ports (1-65535) to find open ones.

Web Server Detection: Identifies the web server running on the target.

SSL Certificate Status: Checks if the site has a valid SSL certificate.

Whois Lookup: Retrieves domain registration and ownership details.

DNS Records Lookup: Fetches A, MX, CNAME, and other DNS records.

Reverse DNS Lookup: Finds the domain name associated with an IP.

HTTP to HTTPS Redirection Check: Determines if HTTP traffic is automatically redirected to HTTPS.

Traceroute: Traces the path packets take to reach the target.

Subdomain Enumeration: Identifies subdomains of the target domain.

HTTP Header Analysis: Extracts HTTP headers to gather server information.

Allowed HTTP Methods Check: Identifies HTTP methods enabled on the server.

CMS Detection: Detects if the target is using popular CMS platforms (WordPress, Joomla, Drupal, etc.).

WordPress Plugin Detection: Scans for common WordPress plugins.

Technology Detection: Identifies technologies like PHP, Nginx, Apache, Django, React, Angular, etc.

Open Redirect Vulnerability Check: Tests if the target is vulnerable to open redirects.
#
# Prerequisites:
1. Install the required Python packages using pip:
##    pip install -r requirements.txt
2. Give execute permissions to the shell script:
##    chmod +x ./darkbyte.sh
3. Run the shell script to install required packages:
##    ./darkbyte.sh
 4. Run the Python script to perform the reconnaissance tasks:
##    sudo python3 darkbyte.py
