# DarkByte
# DNS reconnaissance and server information gathering tool.
# This script performs a series of network reconnaissance tasks on a given domain or IP address, including:
# 1. Retrieving IP information (location, ISP, etc.)
# 2. Resolving the target domain to an IP address
# 3. Pinging the server to check if it's online
# 4. Performing a full port scan (1-65535) to find open ports
# 5. Detecting the web server and checking SSL certificate status
# 6. Fetching Whois information to gather domain registration data
# 7. Checking DNS records for the target domain
#
# Prerequisites:
# 1. Install the required Python packages using pip:
#    pip install -r requirements.txt
# 2. Give execute permissions to the shell script:
#    chmod +x ./darkbyte.sh
# 3. Run the shell script to install required packages:
#    ./darkbyte.sh
# 4. Run the Python script to perform the reconnaissance tasks:
#    sudo python3 darkbyte.py
