import requests
import socket
import os
import time
import subprocess
import concurrent.futures

class DarkByte:

    def __init__(self):
        self.dark_byte = r"""
    ______   _______  _______  _        ______           _________ _______ 
    (  __  \ (  ___  )(  ____ )| \    /\(  ___ \ |\     /|\__   __/(  ____ \
    | (  \  )| (   ) || (    )||  \  / /| (   ) )( \   / )   ) (   | (    \/
    | |   ) || (___) || (____)||  (_/ / | (__/ /  \ (_) /    | |   | (__    
    | |   | ||  ___  ||     __)|   _ (  |  __ (    \   /     | |   |  __)   
    | |   ) || (   ) || (\ (   |  ( \ \ | (  \ \    ) (      | |   | (      
    | (__/  )| )   ( || ) \ \__|  /  \ \| )___) )   | |      | |   | (____/\
    (______/ |/     \||/   \__/|_/    \/|/ \___/    \_/      )_(   (_______/
        """

        print(self.dark_byte)

        self.target = input("\n 🌐 Enter the target domain or IP: ")
        print("\n 🔎 Scanning in progress...")

        print("\n 🌐 Hostname:", self.resolve_hostname(self.target))
        print("\n 🌐 Pinging server:", self.ping_server(self.target))

        self.scan_network(self.target)
        print("\n 📋 Whois Information:\n", self.get_whois_info(self.target))
        print("\n 🔍 IP Information:\n", self.get_ip_info(self.target))
        print("\n 🔒 SSL Certificate Information:\n", self.check_ssl_certificate(self.target))
        print("\n 🔍 DNS Records:\n", self.get_dns_records(self.target))
        print("\n 🔁 Reverse DNS Lookup:\n", self.get_reverse_dns(self.target))
        print("\n 🔧 HTTP to HTTPS Redirection:\n", self.check_http_to_https(self.target))
        print("\n 🚧 Trace Route:\n", self.trace_route(self.target))
        print("\n 🔍 Subdomain Scan:\n", self.scan_subdomains(self.target))
        print("\n 📡 HTTP Headers:\n", self.get_headers(self.target))
        print("\n 🚀 Allowed HTTP Methods:\n", self.check_http_methods(self.target))
        print("\n 🛠️  CMS Detection:\n", self.detect_cms(self.target))
        self.wordpress_plugins(self.target)

    def get_dns_ip(self, dns_name):
        self.dns_name = dns_name
        try:
            return socket.gethostbyname(self.dns_name)
        except socket.gaierror as e:
            return f"Error resolving {self.dns_name}: {str(e)}"
        
    # Get HTTP headers
    def get_headers(self, target):
        self.target = target
        self.url = f"http://{self.target}"
        print("\n📡  Fetching HTTP Headers...")
        try:
            self.response = requests.get(self.url, timeout=5)
            return self.response.headers
        except requests.RequestException as e:
            return {"Error": str(e)}
        
    # Detect CMS
    def detect_cms(self, target):
        self.target = target
        self.url = f"http://{self.target}"
        print("\n🔍 Detecting CMS...")
        try:
            self.response = requests.get(self.url, timeout=5)
            self.headers = self.response.headers
            self.body = self.response.text.lower()

            self.cms_list = {
                "WordPress": ["wp-content", "wp-json", "wordpress"],
                "Drupal": ["x-drupal-cache", "drupal"],
                "Joomla": ["joomla"],
                "Kentico": ["kentico", "CMSPreferredCulture"],
                "Sitecore": ["sitecore", "sc_mode"],
                "Umbraco": ["umbraco"],
                "Magento": ["magento", "mage-"],
                "Shopify": ["shopify"],
                "Squarespace": ["squarespace"],
                "Wix": ["wix.com"],
                "Typo3": ["typo3"],
                "DotNetNuke": ["dnn", "dotnetnuke"],
                "Blogger": ["blogger", "blogspot"],
                "Ghost": ["ghost", "ghost/api"],
                "Grav": ["grav", "grav cms"],
                "Prestashop": ["prestashop"],
                "OpenCart": ["opencart"],
                "BigCommerce": ["bigcommerce"],
                "Webflow": ["webflow"],
                "HubSpot CMS": ["hubspot"],
                "Craft CMS": ["craft"],
                "ExpressionEngine": ["expressionengine"],
                "Concrete5": ["concrete5"],
            }

            self.detected_cms = []

            # Check response headers and body for CMS indicators
            for cms, indicators in self.cms_list.items():
                if any(indicator in self.body or indicator in self.headers.get("x-powered-by", "").lower() for indicator in indicators):
                    self.detected_cms.append(cms)

            return {"CMS": self.detected_cms if self.detected_cms else "Unknown"}

        except requests.RequestException as e:
            return {"Error": str(e)}
        

    def get_ip_info(self, ip=""):
        self.ip = ip
        self.url = f"https://ipinfo.io/{self.get_dns_ip(ip)}/json"
        try:
            self.response = requests.get(self.url)
            return self.response.json()
        except requests.RequestException as e:
            return {"Error": str(e)}

    def resolve_hostname(self, target):
        self.target = target
        time.sleep(0.5)
        return self.get_dns_ip(self.target)

    def ping_server(self, target):
        self.target = target
        self.response = os.system(f"ping -c 1 {self.target} > /dev/null 2>&1")
        return "Online" if self.response == 0 else "Offline"

    def scan_port(self, target, port):
        self.target = target
        self.port = port
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.1)
                return port if sock.connect_ex((self.target, self.port)) == 0 else None
        except socket.error:
            return None

    def scan_network(self, target, max_threads=500):
        self.target = target
        self.max_threads = max_threads
        self.open_ports = []
        print("\n Scanning Network...\n")

        with concurrent.futures.ThreadPoolExecutor(self.max_threads) as executor:
            self.future_to_port = {executor.submit(self.scan_port, self.target, port): port for port in range(1, 1025)}

            for future in concurrent.futures.as_completed(self.future_to_port):
                port = future.result()
                if port:
                    self.open_ports.append(self.port)
                    print(f" Open port: {self.port}")

        return self.open_ports

    def get_whois_info(self, target):
        self.target = target
        try:
            return subprocess.check_output(['whois', self.target], stderr=subprocess.STDOUT).decode('utf-8')
        except subprocess.CalledProcessError as e:
            return {"Error": str(e)}

    def check_ssl_certificate(self, target):
        self.target = target
        try:
            requests.get(f"https://{self.target}", timeout=5, verify=False)
            return {"SSL Certificate Status": "Valid"}
        except requests.exceptions.RequestException as e:
            return {"SSL Certificate Status": "Error", "Error": str(e)}

    def get_dns_records(self, target):
        self.target = target
        try:
            self.response = requests.get(f"https://dns.google/resolve?name={self.target}")
            return self.response.json()
        except requests.exceptions.RequestException as e:
            return {"Error": str(e)}

    def get_reverse_dns(self, ip):
        self.ip = ip
        try:
            return {"Reverse DNS": socket.gethostbyaddr(self.get_dns_ip(self.ip))}
        except socket.herror:
            return {"Reverse DNS": "Not available"}

    def trace_route(self, target):
        self.target = target
        try:
            return {"Traceroute": subprocess.check_output(["traceroute", self.target], stderr=subprocess.STDOUT).decode('utf-8')}
        except subprocess.CalledProcessError as e:
            return {"Error": str(e)}

    def scan_subdomains(self, target):
        self.target = target
        self.subdomains = ["www", "mail", "ftp", "admin", "api"]
        self.found = {}
        for sub in self.subdomains:
            subdomain = f"{sub}.{target}"
            self.ip = self.get_dns_ip(subdomain)
            if "Error" not in self.ip:
                self.found[subdomain] = self.ip
                print(f"    ✅ Found: {subdomain} ({self.ip})")
        return self.found if self.found else "No subdomains found"

    def check_http_methods(self, target):
        self.target = target
        self.url = f"http://{self.target}"
        self.methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "HEAD"]
        self.allowed_methods = []
        
        for method in self.methods:
            try:
                response = requests.request(method, self.url, timeout=5)
                if response.status_code < 405:
                    self.allowed_methods.append(method)
            except requests.RequestException:
                continue

        return {"Allowed HTTP Methods": self.allowed_methods if self.allowed_methods else "Unknown"}


    # WordPress Plugin Detection
    def wordpress_plugins(self, target):
        self.target = target
        self.cms_info = self.detect_cms(self.target)
        
        if "WordPress" in self.cms_info.get("CMS", []):
            print("\n🔍 Checking for common WordPress plugins...")
            
            self.plugins = [
                "wp-content/plugins/akismet",
                "wp-content/plugins/yoast-seo",
                "wp-content/plugins/contact-form-7",
                "wp-content/plugins/wordfence",
                "wp-content/plugins/woocommerce",
                "wp-content/plugins/elementor",
                "wp-content/plugins/revslider",
                "wp-content/plugins/wpforms",
            ]
            
            self.found_plugins = {}
            for plugin in self.plugins:
                url = f"http://{self.target}/{plugin}"
                try:
                    self.response = requests.get(url, timeout=5)
                    if self.response.status_code == 200:
                        self.found_plugins[plugin] = "Exists"
                        print(f"    ✅ Found plugin: {plugin}")
                except requests.RequestException as e:
                    self.found_plugins[plugin] = f"Error: {str(e)}"
            
            return self.found_plugins if self.found_plugins else {"No plugins found"}
        
        return {"Error": "Not a WordPress site"}
    
    # Detect Technologies
    def detect_technologies(self, target):
        self.target = target
        self.url = f"http://{self.target}"
        try:
            self.response = requests.get(self.url, timeout=5)
            self.headers = self.response.headers
            self.body = self.response.text.lower()
            self.tech = []

            if "server" in self.headers:
                self.tech.append(self.headers["server"])
            if "x-powered-by" in headers:
                self.tech.append(self.headers["x-powered-by"])
            if "php" in self.headers.get("x-powered-by", "").lower():
                self.tech.append("PHP")
            if "nginx" in self.headers.get("server", "").lower():
                self.tech.append("Nginx")
            if "apache" in self.headers.get("server", "").lower():
                self.tech.append("Apache")
            if "django" in self.body:
                self.tech.append("Django")
            if "react" in self.body:
                self.tech.append("React")
            if "angular" in self.body:
                self.tech.append("Angular")
            if "vue" in self.body:
                self.tech.append("Vue.js")

            return {"Detected Technologies": self.tech if self.tech else "Unknown"}
        except requests.RequestException as e:
            return {"Error": str(e)}
    
    # Check if HTTP redirects to HTTPS
    def check_http_to_https(self, target):
        self.target = target
        self.url = f"http://{self.target}"
        try:
            self.response = requests.get(self.url, timeout=5, allow_redirects=False)
            if self.response.status_code in [301, 302] and "https://" in self.response.headers.get("Location", ""):
                return {"HTTP to HTTPS Redirection": "Enabled"}
            return {"HTTP to HTTPS Redirection": "Disabled"}
        except requests.RequestException as e:
            return {"Error": str(e)}
    
    # Check for Open Redirect Vulnerability
    def check_open_redirect(self, target):
        self.target = target
        self.payload = "/redirect?url=http://evil.com"
        try:
            self.response = requests.get(f"http://{self.target}{self.payload}", timeout=5, allow_redirects=False)
            if self.response.status_code in [301, 302] and "evil.com" in self.response.headers.get("Location", ""):
                return {"Open Redirect": "Vulnerable"}
            return {"Open Redirect": "Not found"}
        except requests.RequestException as e:
            return {"Error": str(e)}

DarkByte()
