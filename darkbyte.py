import requests
import socket
import os
import time
import subprocess
import socket
import concurrent.futures

# Get IP from DNS name
def get_dns_ip(dns_name):
    try:
        return socket.gethostbyname(dns_name)
    except socket.gaierror as e:
        return f"Error resolving {dns_name}: {str(e)}"

# Get IP info
def get_ip_info(ip=""):
    url = f"https://ipinfo.io/{get_dns_ip(ip)}/json"
    try:
        response = requests.get(url)
        return response.json()
    except requests.RequestException as e:
        return {"Error": str(e)}
    

# Resolve Hostname
def resolve_hostname(target):
    time.sleep(0.5)
    ip_address = get_dns_ip(target)
    return ip_address

# Ping Server
def ping_server(target):
    response = os.system(f"ping -c 1 {target} > /dev/null 2>&1")
    if response == 0:
        return "Online"
    else:
        return "Offline"
    

def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.1)
            if sock.connect_ex((target, port)) == 0:
                return port
    except socket.error:
        return None

def scan_network(target, max_threads=500):
    total_ports = 65535
    open_ports = []
    
    print("\nScanning Network...\n")

    with concurrent.futures.ThreadPoolExecutor(max_threads) as executor:
        future_to_port = {executor.submit(scan_port, target, port): port for port in range(1, total_ports + 1)}

        for count, future in enumerate(concurrent.futures.as_completed(future_to_port), 1):
            port = future.result()
            if port:
                open_ports.append(port)
                print(f" Open port: {port}")

    return open_ports


def get_whois_info(target):
    try:
        return subprocess.check_output(['whois', target], stderr=subprocess.STDOUT).decode('utf-8')
    except subprocess.CalledProcessError as e:
        return {"Error": str(e)}

def check_ssl_certificate(target):
    try:
        response = requests.get(f"https://{target}", timeout=5, verify=False)
        return {"SSL Certificate Status": "Valid"}
    except requests.exceptions.RequestException as e:
        return {"SSL Certificate Status": "Error", "Error": str(e)}

def get_dns_records(target):
    try:
        response = requests.get(f"https://dns.google/resolve?name={target}")
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"Error": str(e)}

def get_reverse_dns(ip):
    try:
        return {"Reverse DNS": socket.gethostbyaddr(get_dns_ip(ip))}
    except socket.herror:
        return {"Reverse DNS": "Not available"}

def trace_route(target):
    try:
        return {"Traceroute": subprocess.check_output(["traceroute", target], stderr=subprocess.STDOUT).decode('utf-8')}
    except subprocess.CalledProcessError as e:
        return {"Error": str(e)}

# Scan for common subdomains
def scan_subdomains(target):
    subdomains = ["www", "mail", "ftp", "admin", "webmail", "api", "dev", "test"]
    found = {}
    for sub in subdomains:
        subdomain = f"{sub}.{target}"
        ip = get_dns_ip(subdomain)
        if "Error" not in ip:
            found[subdomain] = ip
            print(f"    ✅ Found: {subdomain} ({ip})")
    return found if found else "No subdomains found"

# Check allowed HTTP methods
def check_http_methods(target):
    url = f"http://{target}"
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "HEAD"]
    allowed_methods = []
    
    print("\n🔍 Checking Allowed HTTP Methods...")
    for method in methods:
        try:
            response = requests.request(method, url, timeout=5)
            if response.status_code < 405:
                allowed_methods.append(method)
        except requests.RequestException:
            continue

    return {"Allowed HTTP Methods": allowed_methods if allowed_methods else "Unknown"}

# Get HTTP headers
def get_headers(target):
    url = f"http://{target}"
    print("\n📡 Fetching HTTP Headers...")
    try:
        response = requests.get(url, timeout=5)
        return response.headers
    except requests.RequestException as e:
        return {"Error": str(e)}

# Detect CMS
def detect_cms(target):
    url = f"http://{target}"
    print("\n🔍 Detecting CMS...")
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        body = response.text.lower()

        cms_list = {
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

        detected_cms = []

        # Check response headers and body for CMS indicators
        for cms, indicators in cms_list.items():
            if any(indicator in body or indicator in headers.get("x-powered-by", "").lower() for indicator in indicators):
                detected_cms.append(cms)

        return {"CMS": detected_cms if detected_cms else "Unknown"}

    except requests.RequestException as e:
        return {"Error": str(e)}


# Wordpress Plugin Detection
def wordpress_plugins(target):
    cms_info = detect_cms(target)
    
    # Make sure that the CMS info contains 'WordPress'
    if "WordPress" in cms_info.get("CMS", []):
        print("\n🔍 Checking for common WordPress plugins...")
        
        # List of top 100 most popular WordPress plugins
        plugins = [
            "wp-content/plugins/akismet",
            "wp-content/plugins/yoast-seo",
            "wp-content/plugins/contact-form-7",
            "wp-content/plugins/wordfence",
            "wp-content/plugins/woocommerce",
            "wp-content/plugins/elementor",
            "wp-content/plugins/revslider",
            "wp-content/plugins/wpforms",
            "wp-content/plugins/all-in-one-seo-pack",
            "wp-content/plugins/jetpack",
            "wp-content/plugins/advanced-custom-fields",
            "wp-content/plugins/mailchimp-for-wp",
            "wp-content/plugins/elementor-pro",
            "wp-content/plugins/google-analytics-for-wordpress",
            "wp-content/plugins/slider-revolution",
            "wp-content/plugins/simple-social-icons",
            "wp-content/plugins/shortcodes-ultimate",
            "wp-content/plugins/wp-rocket",
            "wp-content/plugins/woocommerce-bookings",
            "wp-content/plugins/woocommerce-subscriptions",
            "wp-content/plugins/woocommerce-advanced-shipping",
            "wp-content/plugins/wpml-multilingual-cms",
            "wp-content/plugins/woo-commerce",
            "wp-content/plugins/cf7-google-sheet-connector",
            "wp-content/plugins/wp-optimize",
            "wp-content/plugins/gutenberg",
            "wp-content/plugins/wp-user-avatar",
            "wp-content/plugins/ultimate-membership-pro",
            "wp-content/plugins/learnpress",
            "wp-content/plugins/wp-multilang",
            "wp-content/plugins/pretty-links",
            "wp-content/plugins/revslider",
            "wp-content/plugins/disable-emojis",
            "wp-content/plugins/related-posts-thumbnails",
            "wp-content/plugins/smush",
            "wp-content/plugins/akismet",
            "wp-content/plugins/cool-timeline",
            "wp-content/plugins/nextgen-gallery",
            "wp-content/plugins/mailpoet",
            "wp-content/plugins/cool-timeline-pro",
            "wp-content/plugins/woo-commerce-payment-gateway",
            "wp-content/plugins/essential-grid",
            "wp-content/plugins/supercache",
            "wp-content/plugins/seo-press",
            "wp-content/plugins/redirection",
            "wp-content/plugins/wp-smtp",
            "wp-content/plugins/litespeed-cache",
            "wp-content/plugins/visitor-analytics",
            "wp-content/plugins/sticky-menu-or-anything-on-scroll",
            "wp-content/plugins/elementor-custom-css",
            "wp-content/plugins/sassy-social-share",
            "wp-content/plugins/ultimate-addons-for-elementor",
            "wp-content/plugins/activecampaign",
            "wp-content/plugins/w3-total-cache",
            "wp-content/plugins/woothemes-sensei",
            "wp-content/plugins/contact-form-7-email-log",
            "wp-content/plugins/wc-vendors",
            "wp-content/plugins/download-monitor",
            "wp-content/plugins/affiliate-wp",
            "wp-content/plugins/wp-smushit",
            "wp-content/plugins/woo-commerce-paypal-express-checkout",
            "wp-content/plugins/woo-commerce-gateway-stripe",
            "wp-content/plugins/woocommerce-pdf-invoices-packing-slips",
            "wp-content/plugins/wp-super-cache",
            "wp-content/plugins/redirection",
            "wp-content/plugins/social-warfare",
            "wp-content/plugins/custom-facebook-feed",
            "wp-content/plugins/ninja-forms",
            "wp-content/plugins/wps-hide-login",
            "wp-content/plugins/yoast-seo-premium",
            "wp-content/plugins/wp-mail-smtp",
            "wp-content/plugins/seopress-pro",
            "wp-content/plugins/yoast-woo-commerce-seo",
            "wp-content/plugins/elementor-custom-forms",
            "wp-content/plugins/hummingbird-performance",
            "wp-content/plugins/smile",
            "wp-content/plugins/wp-mail-smtp-pro",
            "wp-content/plugins/optinmonster",
            "wp-content/plugins/woocommerce-pos",
            "wp-content/plugins/woo-variation-swatches",
            "wp-content/plugins/cashier",
            "wp-content/plugins/woocommerce-gateway-stripe",
            "wp-content/plugins/wordpress-seo",
            "wp-content/plugins/woocommerce-bookings",
            "wp-content/plugins/woocommerce-order-status-manager",
            "wp-content/plugins/advanced-custom-fields-pro",
            "wp-content/plugins/updraftplus",
            "wp-content/plugins/give",
            "wp-content/plugins/woocommerce-subscriptions",
            "wp-content/plugins/wp-migrate-db-pro",
            "wp-content/plugins/woocommerce-product-addons",
            "wp-content/plugins/woocommerce-advanced-shipping",
            "wp-content/plugins/cool-timeline-pro",
            "wp-content/plugins/wishlist",
            "wp-content/plugins/wpfastest-cache",
            "wp-content/plugins/woocommerce-checkout-manager",
            "wp-content/plugins/generateblocks",
            "wp-content/plugins/woo-order-export",
            "wp-content/plugins/smart-slider-3",
            "wp-content/plugins/woo-gateway-authorizenet",
            "wp-content/plugins/leadpages",
            "wp-content/plugins/wp-duplicate-post",
            "wp-content/plugins/captivate",
            "wp-content/plugins/woocommerce-invoices-packing-slips",
            "wp-content/plugins/woo-smart-coupons",
            "wp-content/plugins/yoast-seo-video"
        ]
        
        found_plugins = {}
        for plugin in plugins:
            url = f"http://{target}/{plugin}"
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    found_plugins[plugin] = "Exists"
                    print(f"    ✅ Found plugin: {plugin}")
            except requests.RequestException as e:
                found_plugins[plugin] = f"Error: {str(e)}"
        
        if found_plugins:
            return found_plugins
        else:
            return {"No plugins found"}
    
    else:
        return {"Error": "Not a WordPress site"}


# Detect Technologies
def detect_technologies(target):
    url = f"http://{target}"
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        body = response.text.lower()
        tech = []

        # Server and Backend Technologies
        if "server" in headers:
            tech.append(headers["server"])
        if "x-powered-by" in headers:
            tech.append(headers["x-powered-by"])
        if "php" in headers.get("x-powered-by", "").lower():
            tech.append("PHP")
        if "asp.net" in headers.get("x-powered-by", "").lower():
            tech.append("ASP.NET")
        if "nginx" in headers.get("server", "").lower():
            tech.append("Nginx")
        if "apache" in headers.get("server", "").lower():
            tech.append("Apache")
        if "node.js" in headers.get("x-powered-by", "").lower():
            tech.append("Node.js")
        if "express" in headers.get("x-powered-by", "").lower():
            tech.append("Express.js")
        if "django" in body:
            tech.append("Django")
        if "flask" in body:
            tech.append("Flask")
        if "laravel" in body:
            tech.append("Laravel")
        if "ruby on rails" in body or "rails" in headers.get("x-powered-by", "").lower():
            tech.append("Ruby on Rails")

        # Frontend Frameworks
        if "react" in body:
            tech.append("React")
        if "angular" in body or "ng-app" in body:
            tech.append("Angular")
        if "vue" in body or "vue.js" in body:
            tech.append("Vue.js")
        if "svelte" in body:
            tech.append("Svelte")

        # JavaScript Libraries
        if "jquery" in body:
            tech.append("jQuery")
        if "lodash" in body:
            tech.append("Lodash")
        if "underscore.js" in body:
            tech.append("Underscore.js")
        if "three.js" in body:
            tech.append("Three.js")

        # Cloud Platforms & Hosting
        if "aws" in body or "amazonaws" in body:
            tech.append("AWS")
        if "cloudflare" in headers.get("server", "").lower():
            tech.append("Cloudflare")
        if "firebase" in body:
            tech.append("Google Firebase")
        if "heroku" in headers.get("server", "").lower():
            tech.append("Heroku")
        if "vercel" in body:
            tech.append("Vercel")

        return {"Detected Technologies": tech if tech else "Unknown"}
    except requests.RequestException as e:
        return {"Error": str(e)}
    

# Check if HTTP redirects to HTTPS
def check_http_to_https(target):
    url = f"http://{target}"
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        if response.status_code in [301, 302] and "https://" in response.headers.get("Location", ""):
            return {"HTTP to HTTPS Redirection": "Enabled"}
        return {"HTTP to HTTPS Redirection": "Disabled"}
    except requests.RequestException as e:
        return {"Error": str(e)}
    

# Check for Open Redirect Vulnerability
def check_open_redirect(target):
    payload = "/redirect?url=http://evil.com"
    try:
        response = requests.get(f"http://{target}{payload}", timeout=5, allow_redirects=False)
        if response.status_code in [301, 302] and "evil.com" in response.headers.get("Location", ""):
            return {"Open Redirect": "Vulnerable"}
        return {"Open Redirect": "Not found"}
    except requests.RequestException as e:
        return {"Error": str(e)}


# Main Execution
if __name__ == "__main__":

    dark_byte = r"""
     ______   _______  _______  _        ______           _________ _______ 
    (  __  \ (  ___  )(  ____ )| \    /\(  ___ \ |\     /|\__   __/(  ____ \
    | (  \  )| (   ) || (    )||  \  / /| (   ) )( \   / )   ) (   | (    \/
    | |   ) || (___) || (____)||  (_/ / | (__/ /  \ (_) /    | |   | (__    
    | |   | ||  ___  ||     __)|   _ (  |  __ (    \   /     | |   |  __)   
    | |   ) || (   ) || (\ (   |  ( \ \ | (  \ \    ) (      | |   | (      
    | (__/  )| )   ( || ) \ \__|  /  \ \| )___) )   | |      | |   | (____/\
    (______/ |/     \||/   \__/|_/    \/|/ \___/    \_/      )_(   (_______/
    """

    print(dark_byte)

    target = input("\n🌐 Enter the target domain or IP: ")

    print("\n🔎 Scanning in progress...")

    print("\n🌐 Hostname:", resolve_hostname(target))
    print("\n🌐 Pinging server:", ping_server(target))

    scan_network(target)

    print("\n📋 Whois Information:\n", get_whois_info(target))
    print("\n🔍 IP Information:\n", get_ip_info(target))
    print("\n🔒 SSL Certificate Information:\n", check_ssl_certificate(target))
    print("\n🔍 DNS Records:\n", get_dns_records(target))
    print("\n🔁 Reverse DNS Lookup:\n", get_reverse_dns(target))
    print("\n🔧 HTTP to HTTPS Redirection:\n", check_http_to_https(target))
    print("\n🔧 Check Open Redirection:\n", check_open_redirect(target))
    print("\n🚧 Trace Route:\n", trace_route(target))
    print("\n🔍 Subdomain Scan:\n", scan_subdomains(target))
    print("\n📡 HTTP Headers:\n", get_headers(target))
    print("\n🚀 Allowed HTTP Methods:\n", check_http_methods(target))
    print("\n🛠️ CMS Detection:\n", detect_cms(target))
    print("\n⚙️🔍 Technology Detection:\n", detect_technologies(target))
    print("\n🔍 WordPress Plugins:", wordpress_plugins(target))
