# Use Python 3.12.1
#
# Run:
# python3 iporign.py
#
# Make your selection:
#
# Do you want to check a single IP or a CIDR range? (Enter 'ip' or 'cidr'):
# Enter the CIDR range (e.g., 192.168.0.0/24):
# Enter the keyword to check (e.g., early):

import urllib3
from bs4 import BeautifulSoup
from ipaddress import ip_network, ip_address
import ssl
import time

# Disabling all SSL/TLS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setting cipher suite to resolve DH_KEY_TOO_SMALL error
ssl_context = ssl.create_default_context()
ssl_context.set_ciphers('DEFAULT:@SECLEVEL=1')
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

def get_text_from_html(html_content):
    """Extract text from HTML content."""
    soup = BeautifulSoup(html_content, 'html.parser')
    return soup.get_text()

def get_http_response(ip):
    """Get HTTPS response from a given IP address and extract text."""
    url = f"https://{ip}"
    headers = {'User-Agent': 'Mozilla/5.0'}
    http = urllib3.PoolManager(ssl_context=ssl_context, headers=headers)
    try:
        response = http.request('GET', url, timeout=5)
        return get_text_from_html(response.data.decode('utf-8'))
    except urllib3.exceptions.MaxRetryError as e:
        if "DH_KEY_TOO_SMALL" in str(e):
            print(f"Warning: {url} uses a weak DH key. Ignoring the error and proceeding.")
            try:
                response = http.request('GET', url, timeout=5)
                return get_text_from_html(response.data.decode('utf-8'))
            except Exception:
                print(f"This is not HTTP: {url}")
                return None
        else:
            print(f"This is not HTTP: {url}")
            return None
    except urllib3.exceptions.ConnectTimeoutError:
        print(f"Connection Timeout: {url}")
        return None
    except Exception:
        print(f"This is not HTTP: {url}")
        return None

def check_keyword_in_response(ip, keyword):
    """Check if the keyword exists in the HTTP response from the IP."""
    response_text = get_http_response(ip)
    if response_text and keyword.lower() in response_text.lower():
        print(f"\033[91mMatch! Found '{keyword}' in response from {ip}\033[0m")
    elif response_text is None:
        # Do nothing, error message already printed in get_http_response
        pass
    else:
        print(f"'{keyword}' not found in response from {ip}")

def check_network(cidr, keyword):
    """Check if the keyword exists in the HTTP response from IPs in a network range."""
    network = ip_network(cidr)
    for ip in network:
        check_keyword_in_response(str(ip), keyword)
        time.sleep(5)  # Refresh connection every 5 seconds

def validate_ip(ip):
    """Validate if the input is a valid IP address."""
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False

def validate_cidr(cidr):
    """Validate if the input is a valid CIDR notation."""
    try:
        ip_network(cidr)
        return True
    except ValueError:
        return False

def show_initial_text():
    """Show initial text 'IP Orign' and 'by honeyb33z'."""
    print("""


 ___________   _____      _               _____              _             
|_   _| ___ \ |  _  |    (_)             |_   _|            | |            
  | | | |_/ / | | | |_ __ _  __ _ _ __     | |_ __ __ _  ___| | _____ _ __ 
  | | |  __/  | | | | '__| |/ _` | '_ \    | | '__/ _` |/ __| |/ / _ \ '__|
 _| |_| |     \ \_/ / |  | | (_| | | | |   | | | | (_| | (__|   <  __/ |   
 \___/\_|      \___/|_|  |_|\__, |_| |_|   \_/_|  \__,_|\___|_|\_\___|_|   
                             __/ |                                         
                            |___/                                          
 _              _                            _      _____  _____           
| |            | |                          | |    |____ ||____ |          
| |__  _   _   | |__   ___  _ __   ___ _   _| |__      / /    / /____      
| '_ \| | | |  | '_ \ / _ \| '_ \ / _ \ | | | '_ \     \ \    \ \_  /      
| |_) | |_| |  | | | | (_) | | | |  __/ |_| | |_) |.___/ /.___/ // /       
|___/ \__, |  |_| |_|\___/|_| |_|\___|\__, |___/ \____/ \____//___|
        __/ |                           __/ |                              
       |___/                           |___/                               
                               
                                       
                                       
    """)

if __name__ == "__main__":
    try:
        show_initial_text()
        while True:
            choice = input("Do you want to check a single IP or a CIDR range? (Enter 'ip' or 'cidr'): ").strip().lower()
            if choice in ['ip', 'cidr']:
                break
            else:
                print("Invalid choice. Please enter 'ip' or 'cidr'.")

        if choice == 'ip':
            while True:
                ip = input("Enter the IP address to check: ").strip()
                if validate_ip(ip):
                    break
                else:
                    print("Invalid IP address. Please enter a valid IP address.")
            keyword = input("Enter the keyword to check (e.g., early): ").strip()
            check_keyword_in_response(ip, keyword)
        elif choice == 'cidr':
            while True:
                cidr_range = input("Enter the CIDR range (e.g., 192.168.0.0/24): ").strip()
                if validate_cidr(cidr_range):
                    break
                else:
                    print("Invalid CIDR range. Please enter a valid CIDR range.")
            keyword = input("Enter the keyword to check (e.g., early): ").strip()
            check_network(cidr_range, keyword)
    except KeyboardInterrupt:
        print("\nProcess interrupted by user. Exiting...")
