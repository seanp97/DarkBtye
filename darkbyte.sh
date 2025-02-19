#!/bin/bash

# Update package list
sudo apt update

# Install required packages
sudo apt install -y \
    traceroute \
    whois \
    python3-pip

# Install Python dependencies with --break-system-packages flag
pip3 install requests --break-system-packages
pip3 install nmap --break-system-packages

echo "All required packages and dependencies have been installed."
#!/bin/bash

# Update package list
sudo apt update

# Install required packages
sudo apt install -y \
    nmap \
    traceroute \
    whois \
    python3-requests \
    python3-pip \
    python3-nmap \
    python3-socket \
    python3-argparse \
    python3-pprint \
    python3-subprocess \
    python3-os

# Install Python dependencies
pip3 install requests nmap

echo "All required packages and dependencies have been installed."
