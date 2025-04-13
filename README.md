#WASTT - Web Application Security Testing Tool
WASTT (Web Application Security Testing Tool) is a simple, interactive tool designed to help security professionals and developers test the security of web applications. It includes various modules to test for common vulnerabilities like SQL Injection, XSS, Directory Traversal, and more.

Features
1. Test for SQL Injection
Scan for potential SQL Injection vulnerabilities on the provided target URL.

Detects issues where malicious SQL statements could be executed in the web application.

2. Test for XSS (Cross-Site Scripting)
Scan for possible XSS vulnerabilities in web applications.

Currently under development and planned for future releases.

3. Directory Brute Force
Uses a wordlist to brute-force common directories and files on the target web server.

Helps in identifying exposed resources or hidden endpoints.

4. Detect CMS (Content Management Systems)
Identifies if the target web application is powered by popular CMSs like WordPress, Joomla, etc.

Useful for identifying known CMS-specific vulnerabilities.

5. Check for Security Headers
Checks if common security headers are set, like Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, etc.

Ensures that the web server is taking basic security precautions.

6. Detect WAF (Web Application Firewall)
Attempts to detect if the target website is protected by a Web Application Firewall.

Helps assess the security layer in front of the web application.

7. Fix Security (Simulate SQL Injection Fix)
Simulates a security fix for SQL Injection by suggesting best practices such as input sanitization and using prepared statements.

Not yet implemented but planned for future releases.

8. Server IP Vundo Scan (New Feature!)
IP Scanning: Scan an IP address to check for open ports and their corresponding services.

Port Scanning: Scans common ports (e.g., HTTP, HTTPS, SSH, FTP, MySQL) for potential security risks.

Service Detection: Identifies the services running on open ports, such as web servers, databases, and SSH.

Vulnerability Check: Checks known vulnerabilities associated with the services running on the open ports (e.g., weak passwords, outdated versions).

Installation
To use WASTT, you'll need Python 3.x installed on your system. You will also need the requests library for making HTTP requests and other modules like socket.

1. Clone the repository:
bash
Copy
Edit
git clone https://github.com/yourusername/wastt.git
cd wastt
2. Install dependencies:
bash
Copy
Edit
pip install -r requirements.txt
3. Run the tool:
bash
Copy
Edit
python wastt.py
Usage
Once you run the script, you will be presented with a simple menu where you can choose the security test you want to perform. After selecting a test, you will be prompted to enter the target URL or IP address depending on the test.

Example:
bash
Copy
Edit
Welcome to WASTT - Web Application Security Testing Tool!

Choose an option:
[1] Test for SQL Injection
[2] Test for XSS (Cross-Site Scripting)
[3] Directory Brute Force
[4] Detect CMS (WordPress, Joomla, etc.)
[5] Check for Security Headers
[6] Detect WAF (Web Application Firewall)
[7] Fix Security (Simulate SQL Injection Fix)
[8] Server IP Vundo Scan
[9] Exit

Enter your choice (1-9): 8
Enter the IP address to scan (e.g., 192.168.1.1): 192.168.1.100
Contributing
If you'd like to contribute to the development of WASTT, feel free to fork this repository and submit pull requests. We welcome improvements, bug fixes, and new features!

To Do:
Improve XSS testing functionality.

Enhance the Server IP Vundo Scan with more detailed vulnerability detection using external databases like CVE.

Implement SQL Injection security fixes (sanitization and prepared statements).

Legal Disclaimer
By using WASTT, you acknowledge and agree to the following:

WASTT is a tool intended for educational and research purposes only.

You are solely responsible for any actions taken using this tool.

WASTT should only be used on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal and unethical.

The developers of WASTT are not responsible for any damages, legal issues, or other consequences resulting from the use of this tool.

Use this tool responsibly and always seek permission before testing any web application.

License
This project is licensed under the MIT License - see the LICENSE file for details.
