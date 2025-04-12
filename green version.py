import requests
from urllib.parse import urljoin
from termcolor import colored

# Function to get HTTP response status code
def get_status_code(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code, response
    except requests.exceptions.RequestException:
        return None, None

# Function to check for WAF
def detect_waf(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        # Check for common WAF indicators in headers
        waf_headers = ['X-Sucuri-ID', 'X-Content-Type-Options', 'Server', 'X-XSS-Protection']
        waf_cookies = ['__cfduid', 'AWSALB', 'mod_security', 'wp_sec']

        # Check headers
        for header in waf_headers:
            if header in headers:
                print(colored(f"[+] Possible WAF detected! (Header: {header})", 'green'))
                return True

        # Check cookies
        for cookie in waf_cookies:
            if cookie in response.cookies:
                print(colored(f"[+] Possible WAF detected! (Cookie: {cookie})", 'green'))
                return True

        print(colored("[-] No WAF detected.", 'green'))
        return False

    except requests.exceptions.RequestException as e:
        print(colored(f"[-] Unable to connect to the target: {e}", 'green'))
        return False

# Function to test for SQL Injection
def test_sql_injection(url):
    payload = "' OR '1'='1"
    test_url = url + payload
    status_code, _ = get_status_code(test_url)
    if status_code == 200:
        print(colored(f"[+] Possible SQL Injection vulnerability at {url}", 'green'))
        print(colored("[INFO] Suggested fix: Sanitize user input and use prepared statements.", 'green'))
        print(colored("[INFO] Example fix: Use parameterized queries to prevent SQL Injection.", 'green'))
        return True
    else:
        print(colored(f"[-] No SQL Injection detected at {url}", 'green'))
        return False

# Function to test for XSS
def test_xss(url):
    payload = '<script>alert("XSS")</script>'
    test_url = url + payload
    status_code, response = get_status_code(test_url)
    if status_code == 200:
        if payload in response.text:
            print(colored(f"[+] Possible XSS vulnerability at {url}", 'green'))
        else:
            print(colored(f"[-] No XSS detected at {url}", 'green'))
    else:
        print(colored(f"[-] No XSS detected at {url}", 'green'))

# Function to do directory bruteforce
def dir_bruteforce(base_url, wordlist):
    print(colored(f"[+] Running directory brute force...\n", 'green'))
    for directory in wordlist:
        test_url = urljoin(base_url, directory)
        status_code, _ = get_status_code(test_url)
        if status_code == 200:
            print(colored(f"[+] Found directory: {test_url}", 'green'))
        else:
            print(colored(f"[-] No directory found at {test_url}", 'green'))

# Function to detect CMS (Content Management System)
def detect_cms(url):
    response = requests.get(url)
    if 'wp-content' in response.text:
        print(colored("[+] WordPress CMS detected!", 'green'))
    elif 'Joomla' in response.text:
        print(colored("[+] Joomla CMS detected!", 'green'))
    else:
        print(colored("[-] CMS not detected.", 'green'))

# Function to check for security headers
def check_security_headers(url):
    try:
        response = requests.head(url, timeout=5)
        headers = response.headers
        if "Strict-Transport-Security" not in headers:
            print(colored("[+] Missing Strict-Transport-Security header.", 'green'))
        if "X-Content-Type-Options" not in headers:
            print(colored("[+] Missing X-Content-Type-Options header.", 'green'))
        if "X-XSS-Protection" not in headers:
            print(colored("[+] Missing X-XSS-Protection header.", 'green'))
    except requests.exceptions.RequestException:
        print(colored("[-] Unable to connect to the target.", 'green'))

# Function to fix security issues (simulate the fix for SQL Injection)
def fix_security(url):
    print(colored("\n[*] Attempting to fix security issues for SQL Injection...", 'green'))
    
    # Simulate a check for SQL Injection and offer a "fix"
    if test_sql_injection(url):
        print(colored("\n[INFO] SQL Injection vulnerability detected!", 'green'))
        print(colored("[INFO] Please apply the following fix to secure your application:", 'green'))
        print(colored("[INFO] 1. Sanitize all user inputs.", 'green'))
        print(colored("[INFO] 2. Use prepared statements or parameterized queries in your database queries.", 'green'))
    else:
        print(colored("[INFO] No SQL Injection vulnerabilities found. No fix required.", 'green'))

# Main function to handle user options
def menu():
    print(colored("Welcome to WASTT - Web Application Security Testing Tool!", 'green'))
    
    while True:
        # Prompt for which test to run
        print(colored("\nChoose an option:", 'green'))
        print(colored("[1] Test for SQL Injection", 'green'))
        print(colored("[2] Test for XSS (Cross-Site Scripting)", 'green'))
        print(colored("[3] Directory Brute Force", 'green'))
        print(colored("[4] Detect CMS (WordPress, Joomla, etc.)", 'green'))
        print(colored("[5] Check for Security Headers", 'green'))
        print(colored("[6] Detect WAF (Web Application Firewall)", 'green'))
        print(colored("[7] Fix Security (Simulate SQL Injection Fix)", 'green'))
        print(colored("[8] Exit", 'green'))

        choice = input(colored("\nEnter your choice (1-8): ", 'green')).strip()

        if choice == '8':
            print(colored("Exiting WASTT. Goodbye!", 'green'))
            break

        if choice in ['1', '2', '3', '4', '5', '6', '7']:
            # After choosing an option, prompt for URL
            url = input(colored("Enter the target URL (e.g., http://example.com): ", 'green')).strip()
            # Proceed with the selected test
            if choice == '1':
                test_sql_injection(url)
            elif choice == '2':
                test_xss(url)
            elif choice == '3':
                directory_wordlist = ["admin", "login", "uploads", "images", "files"]
                dir_bruteforce(url, directory_wordlist)
            elif choice == '4':
                detect_cms(url)
            elif choice == '5':
                check_security_headers(url)
            elif choice == '6':
                detect_waf(url)
            elif choice == '7':
                fix_security(url)
        else:
            print(colored("Invalid choice, please select a valid option.", 'green'))

if __name__ == "__main__":
    menu()
