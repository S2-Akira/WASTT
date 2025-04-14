import requests
from urllib.parse import urljoin
from termcolor import colored
import time

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
                print(colored(f"[+] Possible WAF detected! (Header: {header})", 'red'))
                return True

        # Check cookies
        for cookie in waf_cookies:
            if cookie in response.cookies:
                print(colored(f"[+] Possible WAF detected! (Cookie: {cookie})", 'red'))
                return True

        print(colored("[-] No WAF detected.", 'red'))
        return False

    except requests.exceptions.RequestException as e:
        print(colored(f"[-] Unable to connect to the target: {e}", 'red'))
        return False

# Function to test for SQL Injection (Enhanced)
def test_sql_injection(url):
    print(colored("[*] Testing for SQL Injection...", 'red'))

    # Various payloads for SQL Injection testing
    payloads = [
        "' OR '1'='1",  # Basic boolean-based SQLi
        "' OR 1=1 -- ",  # Basic SQLi with comment
        "' OR 'a'='a",   # Simple true condition
        "'; WAITFOR DELAY '0:0:5'--",  # Time-based Blind SQLi (delays response)
        "' OR 1=1#",      # Another boolean-based SQLi
        "union select null, null, null--",  # Union-based SQLi
        "' AND 1=2 --"    # Always false, helps detect blind SQLi
    ]

    vulnerable = False
    for payload in payloads:
        # Determine the correct URL to test with payload
        test_url = url + payload if "?" in url else url + "?" + payload
        
        # Track response time for time-based blind SQL injection
        start_time = time.time()

        try:
            response = requests.get(test_url, timeout=5)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                # Look for error patterns indicating SQL errors
                indicators = [
                    "sql syntax", "mysql_fetch", "ORA-", "unexpected end of SQL command",
                    "Unclosed quotation mark", "quoted string not properly terminated",
                    "ODBC SQL Server Driver", "SQLite3::", "near syntax", "Warning: pg_",
                    "You have an error in your SQL syntax"
                ]
                
                if any(error.lower() in response.text.lower() for error in indicators):
                    print(colored(f"[+] Possible SQL Injection vulnerability at: {test_url}", 'red'))
                    vulnerable = True
                    break  # Stop testing further payloads once vulnerability is found
                
                # Check if response time is significantly delayed (time-based blind SQLi)
                if "WAITFOR DELAY" in payload and response_time > 4:  # Adjust the delay threshold
                    print(colored(f"[+] Possible Time-based Blind SQL Injection at: {test_url}", 'red'))
                    vulnerable = True
                    break  # Stop testing further payloads once vulnerability is found

                # Check for Union-based SQLi (presence of union in payloads)
                if "union select" in payload and "null" in response.text.lower():
                    print(colored(f"[+] Possible Union-based SQL Injection at: {test_url}", 'red'))
                    vulnerable = True
                    break  # Stop testing further payloads once vulnerability is found

        except requests.exceptions.RequestException as e:
            print(colored(f"[-] Error connecting to {test_url}: {e}", 'red'))

    if vulnerable:
        print(colored("[INFO] Suggested fix: Sanitize user input and use prepared statements.", 'red'))
        print(colored("[INFO] Example fix: Use parameterized queries to prevent SQL Injection.", 'red'))
    else:
        print(colored("[-] No SQL Injection vulnerability detected.", 'red'))

    return vulnerable

# Function to test for XSS
def test_xss(url):
    payload = '<script>alert("XSS")</script>'
    test_url = url + payload
    status_code, response = get_status_code(test_url)
    if status_code == 200:
        if payload in response.text:
            print(colored(f"[+] Possible XSS vulnerability at {url}", 'red'))
        else:
            print(colored(f"[-] No XSS detected at {url}", 'red'))
    else:
        print(colored(f"[-] No XSS detected at {url}", 'red'))

# Function to do directory bruteforce
def dir_bruteforce(base_url, wordlist):
    print(colored(f"[+] Running directory brute force...\n", 'red'))
    for directory in wordlist:
        test_url = urljoin(base_url, directory)
        status_code, _ = get_status_code(test_url)
        if status_code == 200:
            print(colored(f"[+] Found directory: {test_url}", 'red'))
        else:
            print(colored(f"[-] No directory found at {test_url}", 'red'))

# Function to detect CMS (Content Management System)
def detect_cms(url):
    response = requests.get(url)
    if 'wp-content' in response.text:
        print(colored("[+] WordPress CMS detected!", 'red'))
    elif 'Joomla' in response.text:
        print(colored("[+] Joomla CMS detected!", 'red'))
    else:
        print(colored("[-] CMS not detected.", 'red'))

# Function to check for security headers
def check_security_headers(url):
    try:
        response = requests.head(url, timeout=5)
        headers = response.headers
        if "Strict-Transport-Security" not in headers:
            print(colored("[+] Missing Strict-Transport-Security header.", 'red'))
        if "X-Content-Type-Options" not in headers:
            print(colored("[+] Missing X-Content-Type-Options header.", 'red'))
        if "X-XSS-Protection" not in headers:
            print(colored("[+] Missing X-XSS-Protection header.", 'red'))
    except requests.exceptions.RequestException:
        print(colored("[-] Unable to connect to the target.", 'red'))

# Function to fix security issues (simulate the fix for SQL Injection)
def fix_security(url):
    print(colored("\n[*] Attempting to fix security issues for SQL Injection...", 'red'))
    
    # Simulate a check for SQL Injection and offer a "fix"
    if test_sql_injection(url):
        print(colored("\n[INFO] SQL Injection vulnerability detected!", 'red'))
        print(colored("[INFO] Please apply the following fix to secure your application:", 'red'))
        print(colored("[INFO] 1. Sanitize all user inputs.", 'red'))
        print(colored("[INFO] 2. Use prepared statements or parameterized queries in your database queries.", 'red'))
    else:
        print(colored("[INFO] No SQL Injection vulnerabilities found. No fix required.", 'red'))

# Main function to handle user options
def menu():
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
        print(colored("[8] Exit", 'red'))

        choice = input(colored("\nEnter your choice (1-8): ", 'red')).strip()

        if choice == '8':
            print(colored("Exiting WASTT. Goodbye!", 'red'))
            break

        if choice in ['1', '2', '3', '4', '5', '6', '7']:
            # After choosing an option, prompt for URL
            url = input(colored("Enter the target URL (e.g., http://example.com): ", 'red')).strip()
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
            print(colored("Invalid choice, please select a valid option.", 'red'))

if __name__ == "__main__":
    menu()
