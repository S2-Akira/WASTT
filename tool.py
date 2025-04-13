import socket
import requests
from urllib.parse import urljoin
from termcolor import colored
import os

# ASCII Art - Integrated into the code
ascii_art = """
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░▒▓████████▓▒░▒▓████████▓▒░
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▓░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░░▒▓██████▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░  ░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░  ░▒▓█▓▒░      ░▒▓█▓▒░
 ░▒▓█████████████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░
"""

# Function to get HTTP response status code
def get_status_code(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code, response
    except requests.exceptions.RequestException:
        return None, None

# Function to test for open ports
def scan_open_ports(ip, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout of 1 second for quick scanning
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Function to identify the services running on open ports
def detect_services(ip, open_ports):
    services = {}
    for port in open_ports:
        if port == 80:
            services[port] = "HTTP (Web Server)"
        elif port == 443:
            services[port] = "HTTPS (Secure Web Server)"
        elif port == 22:
            services[port] = "SSH (Secure Shell)"
        elif port == 21:
            services[port] = "FTP (File Transfer Protocol)"
        elif port == 3306:
            services[port] = "MySQL Database"
        else:
            services[port] = "Unknown Service"
    return services

# Function to check for known vulnerabilities in detected services
def check_vulnerabilities(services):
    known_vulnerabilities = {
        "HTTP (Web Server)": "Check for open HTTP services vulnerable to XSS, CSRF, and SQL Injection.",
        "HTTPS (Secure Web Server)": "Check for SSL/TLS vulnerabilities (e.g., SSL Strip, Heartbleed).",
        "SSH (Secure Shell)": "Ensure strong SSH keys and disable weak ciphers.",
        "FTP (File Transfer Protocol)": "Ensure that anonymous FTP is disabled.",
        "MySQL Database": "Check for weak passwords or outdated MySQL versions.",
        "Unknown Service": "Investigate further for potential security risks."
    }
    for service, description in services.items():
        print(colored(f"[+] Service Detected: {description}", 'red'))
        print(colored(f"   [INFO] Vulnerability Check: {known_vulnerabilities.get(description, 'General Service Security')}", 'yellow'))

# Function to perform IP vulnerability scan
def ip_vundo_scan(ip):
    print(colored(f"\n[+] Scanning IP: {ip} for vulnerabilities...\n", 'red'))
    
    # List of common ports to scan
    common_ports = [22, 80, 443, 21, 3306]
    
    # Scan for open ports
    open_ports = scan_open_ports(ip, common_ports)
    if open_ports:
        print(colored(f"[+] Open Ports on {ip}: {open_ports}", 'red'))
        services = detect_services(ip, open_ports)
        check_vulnerabilities(services)
    else:
        print(colored(f"[-] No open ports found on {ip}.", 'red'))

# Main function to handle user options
def menu():
    print(colored(ascii_art, 'red'))  # Display the ASCII art
    print(colored("Welcome to WASTT - Web Application Security Testing Tool!", 'red'))
    
    while True:
        # Prompt for which test to run
        print(colored("\nChoose an option:", 'red'))
        print(colored("[1] Test for SQL Injection", 'red'))
        print(colored("[2] Test for XSS (Cross-Site Scripting)", 'red'))
        print(colored("[3] Directory Brute Force", 'red'))
        print(colored("[4] Detect CMS (WordPress, Joomla, etc.)", 'red'))
        print(colored("[5] Check for Security Headers", 'red'))
        print(colored("[6] Detect WAF (Web Application Firewall)", 'red'))
        print(colored("[7] Fix Security (Simulate SQL Injection Fix)", 'red'))
        print(colored("[8] Server IP Vundo Scan", 'red'))
        print(colored("[9] Exit", 'red'))

        choice = input(colored("\nEnter your choice (1-9): ", 'red')).strip()

        if choice == '9':
            print(colored("Exiting WASTT. Goodbye!", 'red'))
            break

        if choice in ['1', '2', '3', '4', '5', '6', '7']:
            # After choosing an option, prompt for URL
            url = input(colored("Enter the target URL (e.g., http://example.com): ", 'red')).strip()

            # Validate URL format
            if not url.startswith(('http://', 'https://')):
                print(colored("[-] Invalid URL format. Please include 'http' or 'https'.", 'red'))
                continue

            # Proceed with the selected test
            if choice == '1':
                test_sql_injection(url)
            elif choice == '2':
                test_xss(url)
            elif choice == '3':
                wordlist = ['admin', 'login', 'uploads', 'wp-admin']
                dir_bruteforce(url, wordlist)
            elif choice == '4':
                detect_cms(url)
            elif choice == '5':
                check_security_headers(url)
            elif choice == '6':
                detect_waf(url)
            elif choice == '7':
                print(colored("[INFO] Fix security feature is not yet implemented.", 'yellow'))
        elif choice == '8':
            ip = input(colored("Enter the IP address to scan (e.g., 192.168.1.1): ", 'red')).strip()
            ip_vundo_scan(ip)
        else:
            print(colored("Invalid choice, please select a valid option.", 'red'))

if __name__ == "__main__":
    menu()
