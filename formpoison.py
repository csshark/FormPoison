import requests
import json
from rich.console import Console
from rich.table import Table
import argparse
import sys
import random
from bs4 import BeautifulSoup
import re
import time
from rich.progress import Progress, BarColumn, TimeRemainingColumn
import threading
from selenium import webdriver
from selenium.webdriver.common.by import By
from concurrent.futures import ThreadPoolExecutor, as_completed

skip_flag = False

def monitor_skip():
    global skip_flag
    while True:
        user_input = input("Type 'skip' to move to the next field: ")
        if user_input.strip().lower() == "skip":
            skip_flag = True
            break

console = Console()

def sanitize_user_agent(user_agent):
    return re.sub(r'[^\x00-\x7F]+', '', user_agent)

def show_banner():
    banner = r"""
  [bold blue]Form[/bold blue]                                 .--.
      [bold red]Poison[/bold red]                  ,-.------+-.|  ,-.
                  ,--=======* )"("")===)===* )
                              `-"---==-+-"|  `-"
                                       '--'
    """
    RED = '\033[91m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

    staticbanner = f"""
  {BLUE}Form{RESET}                                 .--.
      {RED}Poison{RESET}                  ,-.------+-.|  ,-.
                  ,--=======* )"("")===)===* )
                              `-"---==-+-"|  `-"
                                       '--'
              Input fields and forms injection framework.
              Developed by: https://github.com/csshark
              Note: This tool is amateur I didn't launch thousands of tests so there might be bugs.
    """

    def animate_falling_texts(texts, banner, start_line=0, end_line=3):
        banner_lines = banner.split('\n')
        max_lines = len(banner_lines) + end_line
        for text in texts:
            for i in range(start_line, max_lines):
                console.clear()
                console.print(banner)
                console.print('\n' * i + "\t" + text)
                time.sleep(0.01)

    falling_words = [
        "<script>",
        "alert(1)",
        "' OR 1=1;",
        "<audio src=x onerror=alert('XSS')>",
        "<noscript>Sorry, your browser does not support Html</noscript>",
        "<img src=x onerror=alert(1)>",
        "1=1; --",
        "<svg/onload=alert(1)>",
        "'; DROP TABLE users; --",
        "<iframe src=javascript:alert(1)>",
        "H4CK3D",
        "403 HTTP",
        "User-Agent: Fake Geco",
        "Error: ",
        "POST /api/endpoint 1.1. HTTP",
        "password",
        "MySQL: error.",
        "[ XSS! ]", 
        "Response: 200 OK"
    ]

    animate_falling_texts(falling_words, banner)
    print(staticbanner)
    print("Framework Initialization Done.")

def parse_cookies(cookie_str):
    cookies = {}
    if cookie_str:
        for pair in cookie_str.split(';'):
            if '=' in pair:
                key, value = pair.strip().split('=', 1)
                cookies[key] = value
    return cookies
def parse_proxy(proxy_url):

    if not proxy_url:
        return None

    if "@" in proxy_url:
        proxy_parts = proxy_url.split("://")[1].split("@")
        auth_part = proxy_parts[0]
        proxy_domain = proxy_parts[1]
        proxy_url = f"http://{proxy_domain}"
        proxy_auth = auth_part
    else:

        proxy_auth = None

    proxies = {
        "http": proxy_url,
        "https": proxy_url
    }

    if proxy_auth:
        proxies["http"] = f"http://{proxy_auth}@{proxy_domain}"
        proxies["https"] = f"https://{proxy_auth}@{proxy_domain}"

    return proxies

def load_payloads(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        console.print(f"[bold red]Error: Payload file '{file_path}' not found.[/bold red]")
        sys.exit(1)
    except json.JSONDecodeError:
        console.print(f"[bold red]Error: Invalid JSON in payload file '{file_path}'.[/bold red]")
        sys.exit(1)

def get_page_content(url, user_agent, proxies=None):
    headers = {'User-Agent': sanitize_user_agent(user_agent)}
    try:
        response = requests.get(url, headers=headers, proxies=proxies)
        return response.text
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error fetching page: {e}[/bold red]")
        return None
        
def get_string_input_fields(content):
    soup = BeautifulSoup(content, 'html.parser')
    input_fields = soup.find_all('input', {'type': ['text', 'password']})
    textareas = soup.find_all('textarea')
    return input_fields + textareas
    

def get_forms_and_inputs(content):
    soup = BeautifulSoup(content, 'html.parser')
    forms = soup.find_all('form')
    forms_with_inputs = []
    for form in forms:
        inputs = form.find_all('input')
        textareas = form.find_all('textarea')
        forms_with_inputs.append((form, inputs + textareas))
    return forms_with_inputs

def find_field_by_name(input_fields, field_name):
    if not field_name:
        return None
    field_name = field_name.lower()
    for field in input_fields:
        field_attrs = [
            field.get('name', '').lower(),
            field.get('id', '').lower(),
            field.get('class', '').lower(),
            field.get('placeholder', '').lower()
        ]
        if any(field_name in attr for attr in field_attrs):
            return field
    return None

def analyze_response_content(content):
    content = content.lower()
    vulnerabilities = []

    # SQL Injection
    sql_errors = [
        r"sql syntax.*error",
        r"warning: mysql",
        r"unclosed quotation mark",
        r"you have an error in your sql syntax",
        r"ora-\d{5}",
        r"postgresql.*error",
        r"sql server.*error"
    ]
    for error in sql_errors:
        if re.search(error, content):
            vulnerabilities.append(f"SQL Injection (Detected: {error})")

    # XSS
    xss_patterns = [
        r"<script>",
        r"alert\(",
        r"onerror=",
        r"onload=",
        r"javascript:"
    ]
    for pattern in xss_patterns:
        if re.search(pattern, content):
            vulnerabilities.append(f"XSS (Detected: {pattern})")

    # HTML Injection
    if "<html>" in content or "<body>" in content:
        vulnerabilities.append("HTML Injection")

    return vulnerabilities

def analyze_response_headers(headers):
    vulnerabilities = []
    security_headers = {
        "Content-Security-Policy": "Missing Content-Security-Policy header",
        "X-Frame-Options": "Missing X-Frame-Options header",
        "X-XSS-Protection": "Missing X-XSS-Protection header",
        "Strict-Transport-Security": "Missing Strict-Transport-Security header",
        "Referrer-Policy": "Missing Referrer-Policy header",
        "Feature-Policy": "Missing Feature-Policy header",
        "Expect-CT": "Missing Expect-CT header",
        "X-Content-Type-Options": "Missing X-Content-Type-Options header"
    }

    for header, message in security_headers.items():
        if header not in headers:
            vulnerabilities.append(message)

    if "Server" in headers:
        vulnerabilities.append(f"Server Information Leak: {headers['Server']}")
    if "X-Powered-By" in headers:
        vulnerabilities.append(f"Framework Information Leak: {headers['X-Powered-By']}")

    return vulnerabilities

def analyze_response(response, payload_category, payload):
    vulnerabilities = []
    content_vulns = analyze_response_content(response.text)
    vulnerabilities.extend(content_vulns)
    header_vulns = analyze_response_headers(response.headers)
    vulnerabilities.extend(header_vulns)

    if payload_category == "SQL" and is_sql_injection_successful(response.text, payload):
        console.print("[bold red]💀 SQL INJECTED 💀[/bold red]")
    elif payload_category == "HTML" and is_xss_successful(response.text, payload):
        console.print("[bold red]💀 XSS INJECTED 💀[/bold red]")

    return vulnerabilities

def is_xss_successful(content, payload):
    return payload.lower() in content.lower()

def is_sql_injection_successful(content, payload):
    sql_errors = [
        r"sql syntax.*error",
        r"warning: mysql",
        r"unclosed quotation mark",
        r"you have an error in your sql syntax",
        r"ora-\d{5}",
        r"postgresql.*error",
        r"sql server.*error"
    ]
    for error in sql_errors:
        if re.search(error, content, re.IGNORECASE) and payload.lower() in content.lower():
            return True
    return False

def test_input_field(url, payloads, threat_type, cookies, user_agent, input_field, method="POST", proxies=None, verbose=False, secs=0):
    global skip_flag
    results = []

    table = Table(title=f"Input Field Test Results (User-Agent: {user_agent}, Method: {method})")
    table.add_column("Payload", style="cyan", no_wrap=False)
    table.add_column("Response Code", justify="right", style="magenta")
    table.add_column("Vulnerability Detected", style="bold green")

    with Progress(BarColumn(bar_width=None), "[progress.percentage]{task.percentage:>3.0f}%", TimeRemainingColumn(), console=console) as progress:
        task = progress.add_task("[cyan]Testing...", total=len(payloads))

        for payload in payloads:
            if skip_flag:
                console.print(f"[bold yellow]Skipped to field: {input_field.get('name', 'input_field')}[/bold yellow]")
                skip_flag = False
                break

            try:
                headers = {'User-Agent': sanitize_user_agent(user_agent)}
                data = {
                    input_field.get('name', 'input_field'): payload['inputField']
                }

                if method == "GET":
                    response = requests.get(url, params=data, cookies=cookies, headers=headers, proxies=proxies)
                elif method == "POST":
                    response = requests.post(url, data=data, cookies=cookies, headers=headers, proxies=proxies)
                elif method == "PUT":
                    response = requests.put(url, data=data, cookies=cookies, headers=headers, proxies=proxies)
                elif method == "DELETE":
                    response = requests.delete(url, data=data, cookies=cookies, headers=headers, proxies=proxies)

                vulnerabilities = analyze_response(response, payload['category'], payload['inputField'])

                results.append({
                    "payload": payload['inputField'],
                    "response_code": response.status_code,
                    "vulnerabilities": vulnerabilities
                })

                table.add_row(payload['inputField'], str(response.status_code), ", ".join(vulnerabilities))
                if verbose:
                    console.print(f"[bold blue]Testing payload: {payload['inputField']}[/bold blue]")
                    console.print(f"[bold blue]Response code: {response.status_code}[/bold blue]")
                    console.print(f"[bold blue]Vulnerabilities detected: {', '.join(vulnerabilities)}[/bold blue]")
            except requests.exceptions.RequestException as e:
                results.append({
                    "payload": payload['inputField'],
                    "response_code": "Error",
                    "vulnerabilities": [f"Request Failed: {str(e)}"]
                })
                table.add_row(payload['inputField'], "Error", f"Request Failed: {str(e)}")
                if verbose:
                    console.print(f"[bold red]Error testing payload: {payload['inputField']}[/bold red]")
                    console.print(f"[bold red]Error: {str(e)}[/bold red]")

            progress.update(task, advance=1)
            if secs > 0:
                time.sleep(secs)

    console.print(table)
    with open("test_results.json", "w") as f:
        json.dump(results, f, indent=4)
    console.print(f"[bold green]Test results saved to 'test_results.json'[/bold green]")

def test_all_forms(url, payloads, threat_type, cookies, user_agent, method="POST", proxies=None, verbose=False, secs=0):
    forms_with_inputs = get_forms_and_inputs(get_page_content(url, user_agent, proxies))
    for form, inputs in forms_with_inputs:
        console.print(f"[bold cyan]Testing form with {len(inputs)} inputs[/bold cyan]")
        for input_field in inputs:
            console.print(f"[bold cyan]Testing input field: {input_field.get('name', 'input_field')}[/bold cyan]")
            test_input_field(url, payloads, threat_type, cookies, user_agent, input_field, method, proxies, verbose, secs)
def main():
    console.clear()
    show_banner()
    parser = argparse.ArgumentParser(description="Over 500 payloads included!")
    parser.add_argument("url", help="Form URL")
    parser.add_argument("-t", "--threat", choices=["HTML", "Java", "SQL"], help="Threat type to test (HTML, Java, SQL)")
    parser.add_argument("-p", "--payloads", default="payloads.json", help="JSON file with payloads")
    parser.add_argument("--cookies", help="Cookies: 'key1=value1; key2=value2'")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--method", default="POST", choices=["GET", "POST", "PUT", "DELETE"], help="HTTP method to use (default: POST)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("--fieldname", help="Specific input field name to test (e.g., 'Last Name')")
    parser.add_argument("-s", "--seconds", type=float, default=0, help="Delay between requests in seconds")

    if len(sys.argv) == 1:
        console.print("[bold red]Enter valid command[/bold red]")
        parser.print_help()
        sys.exit()

    args = parser.parse_args()

    if not args.url.startswith(('http://', 'https://')):
        args.url = f'https://{args.url}'
        console.print(f"[bold yellow]Automatically added 'https://' to the URL: {args.url}[/bold yellow]")

    payloads = load_payloads(args.payloads)
    if args.threat:
        payloads = [payload for payload in payloads if payload['category'] == args.threat]
        console.print(f"[bold green]Filtered payloads for threat type: {args.threat}[/bold green]")

    cookies = parse_cookies(args.cookies) if args.cookies else {}
    proxies = parse_proxy(args.proxy) if args.proxy else None

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.198 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.65 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; GT-I9505 Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
        "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/114.0",
        "Mozilla/5.0 (iPad; CPU OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15",
        "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
        "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.137 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
        "Mozilla/5.0 (Linux; Android 9; Redmi Note 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.126 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0",
        "Mozilla/5.0 (Linux; U; Android 4.2.2; en-us; GT-P5113 Build/JDQ39) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Safari/534.30",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19577",
        "Mozilla/5.0 (X11) AppleWebKit/62.41 (KHTML, like Gecko) Edge/17.10859 Safari/452.6",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14931",
        "Chrome (AppleWebKit/537.1; Chrome50.0; Windows NT 6.3) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.9200",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.16) Gecko/20120421 Firefox/11.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:11.0) Gecko Firefox/11.0",
        "Mozilla/5.0 (Windows NT 6.1; U;WOW64; de;rv:11.0) Gecko Firefox/11.0",
        "Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko Firefox/11.0",
        "Mozilla/6.0 (Macintosh; I; Intel Mac OS X 11_7_9; de-LI; rv:1.9b4) Gecko/2012010317 Firefox/10.0a4",
        "Mozilla/5.0 (Macintosh; I; Intel Mac OS X 11_7_9; de-LI; rv:1.9b4) Gecko/2012010317 Firefox/10.0a4",
        "Mozilla/5.0 (X11; Mageia; Linux x86_64; rv:10.0.9) Gecko/20100101 Firefox/10.0.9",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:9.0a2) Gecko/20111101 Firefox/9.0a2",
        "Mozilla/5.0 (Windows NT 6.2; rv:9.0.1) Gecko/20100101 Firefox/9.0.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:9.0) Gecko/20100101 Firefox/9.0",
        "Mozilla/5.0 (Windows NT 5.1; rv:8.0; en_us) Gecko/20100101 Firefox/8.0",
        "Mozilla/5.0 (Windows NT 6.1; rv:6.0) Gecko/20100101 Firefox/7.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0a2) Gecko/20110613 Firefox/6.0a2",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0a2) Gecko/20110612 Firefox/6.0a2",
        "Mozilla/5.0 (X11; Linux i686; rv:6.0) Gecko/20100101 Firefox/6.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.90 Safari/537.36",
        "Mozilla/5.0 (X11; NetBSD) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",
        "Mozilla/5.0 (X11; CrOS i686 3912.101.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.60 Safari/537.17",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1309.0 Safari/537.17",
        "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.15 (KHTML, like Gecko) Chrome/24.0.1295.0 Safari/537.15",
        "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.14 (KHTML, like Gecko) Chrome/24.0.1292.0 Safari/537.14",
        "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.13 (KHTML, like Gecko) Chrome/24.0.1290.1 Safari/537.13",
        "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.13 (KHTML, like Gecko) Chrome/24.0.1290.1 Safari/537.13"
    ]

    page_content = None
    for user_agent in user_agents:
        page_content = get_page_content(args.url, user_agent, proxies)
        if page_content:
            break

    if not page_content:
        console.print("[bold red]Failed to fetch page content.[/bold red]")
        sys.exit()

    input_fields = get_string_input_fields(page_content)
    console.print(f"[bold green]{len(input_fields)} String input fields found[/bold green]")

    random.shuffle(user_agents)

    for user_agent in user_agents:
        console.print(f"[bold green]Testing with User-Agent: {user_agent}[/bold green]")

    if args.fieldname:
        field = find_field_by_name(input_fields, args.fieldname)
        if field:
            console.print(f"[bold yellow]Focusing only on input field: {args.fieldname}[/bold yellow]")
            test_input_field(args.url, payloads, args.threat, cookies, user_agent, field, args.method, proxies, args.verbose, args.seconds)
        else:
            console.print(f"[bold red]No input field found with name '{args.fieldname}'[/bold red]")
            sys.exit(1)
    else:
        test_all_forms(args.url, payloads, args.threat, cookies, user_agent, args.method, proxies, args.verbose, args.seconds)

if __name__ == "__main__":
    main()
