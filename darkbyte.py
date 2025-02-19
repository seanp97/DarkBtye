import requests
import argparse
import socket
import nmap
import os
import time
from pprint import pprint
import subprocess

# Get IP info
def get_ip_info(ip=""):
    url = f"https://ipinfo.io/{ip}/json"
    try:
        response = requests.get(url)
        data = response.json()
        return {
            "IP": data.get("ip", "N/A"),
            "City": data.get("city", "N/A"),
            "Region": data.get("region", "N/A"),
            "Country": data.get("country", "N/A"),
            "Location": data.get("loc", "N/A"),
            "ISP": data.get("org", "N/A"),
            "Timezone": data.get("timezone", "N/A")
        }
    except requests.RequestException as e:
        return {"Error": str(e)}

# Get Server Info
def get_server_info(target):
    info = {}

    print("\n[1] Resolving Hostname and IP...")
    time.sleep(0.5)
    try:
        ip_address = socket.gethostbyname(target)
        info["IP Address"] = ip_address
        print(f"    ✅ Resolved: {ip_address}")
    except socket.gaierror:
        info["IP Address"] = "Could not resolve"
        print("    ❌ Could not resolve IP address")

    print("\n[2] Pinging the Server...")
    time.sleep(0.5)
    response = os.system(f"ping -c 1 {target} > /dev/null 2>&1")
    if response == 0:
        info["Ping Status"] = "Online"
        print("    ✅ Server is online")
    else:
        info["Ping Status"] = "Offline"
        print("    ❌ Server is offline or not responding")

    print("\n[3] Performing a Port Scan (1-65535)...(this may take a while)")
    time.sleep(0.5)
    nm = nmap.PortScanner()
    try:
        nm.scan(target, '1-65535', '-sV', False)
    except Exception as e:
        print(f"Error during scan: {e}")
        open_ports = {}
        info["Open Ports"] = open_ports

    if target in nm.all_hosts():
        open_ports = {}
        for port in nm[target]['tcp']:
            service_name = nm[target]['tcp'][port]['name']
            open_ports[port] = service_name
            print(f"    🔍 Found open port {port} ({service_name})")
    else:
        open_ports = {}
        print("    ❌ No open ports detected or scan failed.")

    info["Open Ports"] = open_ports

    print("\n[4] Detecting Web Server & Headers...")
    time.sleep(0.5)
    try:
        response = requests.get(f"http://{target}", timeout=5)
        info["Web Server"] = response.headers.get("Server", "Unknown")
        info["Powered By"] = response.headers.get("X-Powered-By", "Unknown")
        print(f"    ✅ Web Server: {info['Web Server']}")
        print(f"    ✅ X-Powered-By: {info['Powered By']}")
    except requests.exceptions.RequestException:
        info["Web Server"] = "Not reachable"
        print("    ❌ Could not reach web server")

    print("\n[5] Checking for Common Database Ports...")
    time.sleep(0.5)
    db_ports = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB"}
    detected_dbs = [db for port, db in db_ports.items() if port in open_ports]
    info["Databases"] = detected_dbs if detected_dbs else "Unknown"

    if detected_dbs:
        print(f"    ✅ Detected Databases: {', '.join(detected_dbs)}")
    else:
        print("    ❌ No common database services detected")

    return info


def get_whois_info(target):
    try:
        whois_info = subprocess.check_output(['whois', target], stderr=subprocess.STDOUT)
        return whois_info.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return {"Error": str(e)}


def check_ssl_certificate(target):
    url = f"https://{target}"
    try:
        response = requests.get(url, timeout=5, verify=False)
        cert = response.cert
        if cert:
            return {
                "SSL Certificate Status": "Valid",
                "Issuer": cert.get("issuer", "Unknown"),
                "Validity Period": f"From {cert.get('notBefore', 'Unknown')} to {cert.get('notAfter', 'Unknown')}"
            }
        else:
            return {"SSL Certificate Status": "Invalid or No SSL Certificate"}
    except requests.exceptions.RequestException as e:
        return {"SSL Certificate Status": "Error", "Error": str(e)}

# Check DNS records
def get_dns_records(target):
    try:
        dns_info = requests.get(f"https://dns.google/resolve?name={target}")
        data = dns_info.json()
        return {
            "DNS Records": data.get("Answer", "No DNS records found")
        }
    except requests.exceptions.RequestException as e:
        return {"Error": str(e)}
    

def get_reverse_dns(ip):
    try:
        host = socket.gethostbyaddr(ip)
        return {"Reverse DNS": host[0]}
    except socket.herror:
        return {"Reverse DNS": "Not available"}
    

def trace_route(target):
    try:
        result = subprocess.check_output(["traceroute", target], stderr=subprocess.STDOUT)
        return {"Traceroute": result.decode('utf-8')}
    except subprocess.CalledProcessError as e:
        return {"Error": str(e)}
    

def get_dns_ip(dns_name):
    try:
        # Get the IP address of the DNS server
        dns_ip = socket.gethostbyname(dns_name)
        return dns_ip
    except socket.gaierror as e:
        return f"Error resolving {dns_name}: {str(e)}"


# Main execution
if __name__ == "__main__":

    target = input("\n🌐 Enter the target domain or IP: ")

    ip = get_dns_ip(target)

    ip_info = get_ip_info(ip)
    print("\n🔍 IP Information:\n")
    for key, value in ip_info.items():
        print(f"    {key}: {value}")

    print("\n🔎 Scanning in progress...\n")
    time.sleep(1)

    results = get_server_info(ip)

    print("\n📌 Server Scan Report:\n")
    pprint(results)

    # Whois information
    print("\n📋 Whois Information:\n")
    whois_info = get_whois_info(ip)
    pprint(whois_info)

    # SSL Certificate Status
    print("\n🔒 SSL Certificate Information:\n")
    ssl_info = check_ssl_certificate(ip)
    pprint(ssl_info)

    # DNS Records
    print("\n🔍 DNS Records:\n")
    dns_info = get_dns_records(ip)
    pprint(dns_info)

    # DNS Lookup
    print("\n🔁 Reverse DNS Lookup:\n")
    reverse_dns_info = get_reverse_dns(ip)
    pprint(reverse_dns_info)

    # Trace Route
    print("\n🚧 Trace Route:\n")
    trace_route_info = trace_route(ip)
    pprint(trace_route_info)
