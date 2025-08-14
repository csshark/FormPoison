import aiohttp
import asyncio
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
import urllib3
import ssl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

skip_flag = False

async def monitor_skip():
    global skip_flag
    while True:
        user_input = await asyncio.get_event_loop().run_in_executor(None, input, "Type 'skip' to move to the next field: ")
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

def filter_payloads(payloads, filter_patterns):
    if not filter_patterns:
        return payloads

    filtered_payloads = []
    for payload in payloads:
        for pattern in filter_patterns:
            if pattern.lower() in payload['inputField'].lower():
                filtered_payloads.append(payload)
                break 

    return filtered_payloads

async def get_page_content(url, user_agent, proxies=None, ssl_cert=None, ssl_key=None, ssl_verify=False):
    headers = {'User-Agent': sanitize_user_agent(user_agent)}
    try:
        ssl_context = ssl.create_default_context()
        if ssl_cert and ssl_key:
            ssl_context.load_cert_chain(ssl_cert, ssl_key)
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
            async with session.get(url, headers=headers, proxy=proxies.get('http') if proxies else None, ssl=ssl_verify) as response:
                return await response.text()
    except Exception as e:
        console.print(f"[bold red]Error fetching page: {e}[/bold red]")
        return None

def get_page_content_with_selenium(url):
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')  
    driver = webdriver.Chrome(options=options)
    driver.get(url)
    time.sleep(3)  
    content = driver.page_source
    driver.quit()
    return content

async def test_input_field(url, payloads, threat_type, cookies, user_agent, input_field, method="POST", proxies=None, ssl_cert=None, ssl_key=None, ssl_verify=False, verbose=False, verbose_all=False, filter, secs=0):
    global skip_flag
    results = []
    positive_responses = 0
    threshold = len(payloads) * 0.5

    table = Table(title=f"Input Field Test Results (User-Agent: {user_agent}, Method: {method})")
    table.add_column("Payload", style="cyan", no_wrap=False)
    table.add_column("Response Code", justify="right", style="magenta")
    table.add_column("Vulnerability Detected", style="bold green")

    async def test_payload(payload):
        if skip_flag:
            console.print(f"[bold yellow]Skipped to field: {input_field.get('name', 'input_field')}[/bold yellow]")
            skip_flag = False
            return

        try:
            headers = {'User-Agent': sanitize_user_agent(user_agent)}
            data = {
                input_field.get('name', 'input_field'): payload['inputField']
            }

            ssl_context = ssl.create_default_context()
            if ssl_cert and ssl_key:
                ssl_context.load_cert_chain(ssl_cert, ssl_key)

            cookie_jar = aiohttp.CookieJar()
            for key, value in cookies.items():
                cookie_jar.update_cookies({key: value})

            async with aiohttp.ClientSession(cookie_jar=cookie_jar, connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
                if method == "GET":
                    async with session.get(url, params=data, headers=headers, proxy=proxies.get('http') if proxies else None, ssl=ssl_verify) as response:
                        content = await response.text()
                        status_code = response.status
                elif method == "POST":
                    async with session.post(url, data=data, headers=headers, proxy=proxies.get('http') if proxies else None, ssl=ssl_verify) as response:
                        content = await response.text()
                        status_code = response.status
                elif method == "PUT":
                    async with session.put(url, data=data, headers=headers, proxy=proxies.get('http') if proxies else None, ssl=ssl_verify) as response:
                        content = await response.text()
                        status_code = response.status
                elif method == "DELETE":
                    async with session.delete(url, data=data, headers=headers, proxy=proxies.get('http') if proxies else None, ssl=ssl_verify) as response:
                        content = await response.text()
                        status_code = response.status

                if status_code == 200:
                    positive_responses += 1

                vulnerabilities = analyze_response(content, response.headers, payload['category'], payload['inputField'])

                results.append({
                    "payload": payload['inputField'],
                    "response_code": status_code,
                    "vulnerabilities": vulnerabilities
                })

                table.add_row(payload['inputField'], str(status_code), ", ".join(vulnerabilities))
                if verbose or verbose_all:
                    console.print(f"[bold blue]Testing payload: {payload['inputField']}[/bold blue]")
                    console.print(f"[bold blue]Response code: {status_code}[/bold blue]")
                    console.print(f"[bold blue]Vulnerabilities detected: {', '.join(vulnerabilities)}[/bold blue]")
                    if verbose_all:
                        console.print(f"[bold yellow]Response content:[/bold yellow]")
                        console.print(f"[yellow]{content}[/yellow]")
        except Exception as e:
            results.append({
                "payload": payload['inputField'],
                "response_code": "Error",
                "vulnerabilities": [f"Request Failed: {str(e)}"]
            })
            table.add_row(payload['inputField'], "Error", f"Request Failed: {str(e)}")
            if verbose or verbose_all:
                console.print(f"[bold red]Error testing payload: {payload['inputField']}[/bold red]")
                console.print(f"[bold red]Error: {str(e)}[/bold red]")

    with Progress(BarColumn(bar_width=None), "[progress.percentage]{task.percentage:>3.0f}%", TimeRemainingColumn(), console=console) as progress:
        task = progress.add_task("[cyan]Testing...", total=len(payloads))

        await asyncio.gather(*[test_payload(payload) for payload in payloads])

    if positive_responses > threshold:
        console.print(f"[bold red]Too many positive responses were given ({positive_responses}/{len(payloads)}). You might consider this result as false-positive.[/bold red]")

    console.print(table)
    with open("test_results.json", "w") as f:
        json.dump(results, f, indent=4)
    console.print(f"[bold green]Test results saved to 'test_results.json'[/bold green]")

async def test_login_input_fields(url, payloads, cookies, user_agent, input_fields, proxies=None, verbose=False, verbose_all=False, secs=0):
    global skip_flag
    results = []

    table = Table(title=f"Login Input Field Test Results (User-Agent: {user_agent})")
    table.add_column("Login Payload", style="cyan", no_wrap=False)
    table.add_column("Password Payload", style="cyan", no_wrap=False)
    table.add_column("Response Code", justify="right", style="magenta")
    table.add_column("Vulnerability Detected", style="propbold green")

    login_field = None
    password_field = None

    # selenium is goat
    content = get_page_content_with_selenium(url)
    soup = BeautifulSoup(content, 'html.parser')
    input_fields = soup.find_all('input', {'type': ['text', 'password', 'email']})

    console.print(f"[bold yellow]Found input fields:[/bold yellow]")
    for field in input_fields:
        name = field.get('name', '')
        id_ = field.get('id', '')
        placeholder = field.get('placeholder', '')
        console.print(f"[bold blue]Field: name={name}, id={id_}, placeholder={placeholder}[/bold blue]")

    for field in input_fields:
        name = field.get('name', '').lower()
        id_ = field.get('id', '').lower()
        placeholder = field.get('placeholder', '').lower()

        login_keywords = ['login', 'username', 'user', 'email', 'e-mail', 'mail', 'userid', 'user_id', 'loginname', 'account', 'mat-input-1'] 
        if any(keyword in name or keyword in id_ or keyword in placeholder for keyword in login_keywords):
            login_field = field
            console.print(f"[bold green]Found login field: id={id_}[/bold green]")  # Debug

        # Szukaj pola hasła
        password_keywords = ['password', 'pass', 'passwd', 'pwd', 'userpassword', 'user_pass']
        if any(keyword in name or keyword in id_ or keyword in placeholder for keyword in password_keywords):
            password_field = field
            console.print(f"[bold green]Found password field: {name}[/bold green]")  # Debug

    if not login_field or not password_field:
        console.print("[bold yellow]No login or password fields found for login testing.[/bold yellow]")
        return

    login_payloads = ["admin", "test", "user", "' OR 1='1"]
    sql_payloads = [payload['inputField'] for payload in payloads if payload['category'] == "SQL"]

    skip_thread = threading.Thread(target=monitor_skip)
    skip_thread.daemon = True
    skip_thread.start()

    with Progress() as progress:
        task = progress.add_task("[cyan]Testing login...", total=len(login_payloads) * len(sql_payloads))

        for login_payload in login_payloads:
            for password_payload in sql_payloads:
                try:
                    if skip_flag:
                        console.print(f"[bold yellow]Skipped to field {login_field.get('name', 'login')}[/bold yellow]")
                        skip_flag = False
                        break

                    headers = {'User-Agent': sanitize_user_agent(user_agent)}
                    data = {
                        login_field.get('name', 'login'): login_payload,
                        password_field.get('name', 'password'): password_payload
                    }
                    async with aiohttp.ClientSession() as session:
                        async with session.post(url, data=data, cookies=cookies, headers=headers, proxy=proxies.get('http') if proxies else None) as response:
                            content = await response.text()
                            status_code = response.status

                            vulnerabilities = analyze_response(content, response.headers, "SQL", password_payload)

                            results.append({
                                "login_payload": login_payload,
                                "password_payload": password_payload,
                                "response_code": status_code,
                                "vulnerabilities": vulnerabilities
                            })

                            table.add_row(login_payload, password_payload, str(status_code), ", ".join(vulnerabilities))
                            if verbose or verbose_all:
                                console.print(f"[bold blue]Testing login: {login_payload}, password: {password_payload}[/bold blue]")
                                console.print(f"[bold blue]Response code: {status_code}[/bold blue]")
                                console.print(f"[bold blue]Vulnerabilities detected: {', '.join(vulnerabilities)}[/bold blue]")
                                if verbose_all:
                                    console.print(f"[bold yellow]Response content:[/bold yellow]")
                                    console.print(f"[yellow]{content}[/yellow]")
                except Exception as e:
                    results.append({
                        "login_payload": login_payload,
                        "password_payload": password_payload,
                        "response_code": "Error",
                        "vulnerabilities": [f"Request Failed: {str(e)}"]
                    })
                    table.add_row(login_payload, password_payload, "Error", f"Request Failed: {str(e)}")
                    if verbose or verbose_all:
                        console.print(f"[bold red]Error testing login: {login_payload}, password: {password_payload}[/bold red]")
                        console.print(f"[bold red]Error: {str(e)}[/bold red]")
                progress.update(task, advance=1)

    console.print(table)

    with open("login_test_results.json", "w") as f:
        json.dump(results, f, indent=4)

    console.print(f"[bold green]Login test results saved to 'login_test_results.json'[/bold green]")


def get_string_input_fields(content):
    soup = BeautifulSoup(content, 'html.parser')
    input_fields = soup.find_all('input', {'type': ['text', 'password', 'email']})
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

def analyze_response(content, headers, payload_category, payload):
    vulnerabilities = []
    content_vulns = analyze_response_content(content)
    vulnerabilities.extend(content_vulns)
    header_vulns = analyze_response_headers(headers)
    vulnerabilities.extend(header_vulns)

    if payload_category == "SQL" and is_sql_injection_successful(content, payload):
        console.print("[bold red]💀 SQL INJECTED 💀[/bold red]")
    elif payload_category == "HTML" and is_xss_successful(content, payload):
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

async def test_all_forms(url, payloads, threat_type, cookies, user_agent, method="POST", proxies=None, ssl_cert=None, ssl_key=None, ssl_verify=False, verbose=False, secs=0):
    forms_with_inputs = get_forms_and_inputs(await get_page_content(url, user_agent, proxies, ssl_cert, ssl_key, ssl_verify))
    for form, inputs in forms_with_inputs:
        console.print(f"[bold cyan]Testing form with {len(inputs)} inputs[/bold cyan]")
        for input_field in inputs:
            console.print(f"[bold cyan]Testing input field: {input_field.get('name', 'input_field')}[/bold cyan]")
            await test_input_field(url, payloads, threat_type, cookies, user_agent, input_field, method, proxies, ssl_cert, ssl_key, ssl_verify, verbose, secs)

async def main():
    console.clear()
    show_banner()
    parser = argparse.ArgumentParser(description="Over 500 payloads included!")
    parser.add_argument("url", help="Form URL")
    parser.add_argument("-t", "--threat", choices=["HTML", "Java", "SQL"], help="Threat type to test (HTML, Java, SQL)")
    parser.add_argument("-p", "--payloads", default="payloads.json", help="JSON file with payloads")
    parser.add_argument("--cookies", help="Cookies: 'key1=value1; key2=value2'")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://login:password@proxy.com)")
    parser.add_argument("--ssl-cert", help="Path to SSL certificate file (e.g., cert.pem)")
    parser.add_argument("--ssl-key", help="Path to SSL private key file (e.g., key.pem)")
    parser.add_argument("--ssl-verify", action="store_true", help="Verify SSL certificate (default: False)")
    parser.add_argument("--method", default="POST", choices=["GET", "POST", "PUT", "DELETE"], help="HTTP method to use (default: POST)")
    parser.add_argument("--filter", help="Filter payloads by user-defined patterns (e.g., '<meta>, <script>, onclick')")
    parser.add_argument("--login", action="store_true", help="Enable login testing for login and password fields")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("--verbose-all", action="store_true", help="Enable verbose mode with response content")
    parser.add_argument("--fieldname", help="Specific input field name to test (e.g., 'username')")
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

    if args.filter:
        filter_patterns = [pattern.strip() for pattern in args.filter.split(",")]
        payloads = filter_payloads(payloads, filter_patterns)
        console.print(f"[bold green]Filtered payloads based on patterns: {', '.join(filter_patterns)}[/bold green]")

    if args.threat:
        payloads = [payload for payload in payloads if payload['category'] == args.threat]
        console.print(f"[bold green]Filtered payloads for threat type: {args.threat}[/bold green]")

    cookies = parse_cookies(args.cookies) if args.cookies else {}
    proxies = parse_proxy(args.proxy) if args.proxy else None

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv=89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0. containers2.124 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
    ]

    page_content = None
    for user_agent in user_agents:
        page_content = await get_page_content(args.url, user_agent, proxies, args.ssl_cert, args.ssl_key, args.ssl_verify)
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
            await test_input_field(args.url, payloads, args.threat, cookies, user_agent, field, args.method, proxies, args.ssl_cert, args.ssl_key, args.ssl_verify, args.verbose, args.verbose_all, args.seconds)
        else:
            console.print(f"[bold red]No input field found with name '{args.fieldname}'[/bold red]")
            sys.exit(1)
    elif args.login:
        console.print(f"[bold green]Testing login fields with User-Agent: {user_agent}[/bold green]")
        await test_login_input_fields(args.url, payloads, cookies, user_agent, input_fields, proxies, args.verbose, args.verbose_all, args.seconds)
    else:
        await test_all_forms(args.url, payloads, args.threat, cookies, user_agent, args.method, proxies, args.ssl_cert, args.ssl_key, args.ssl_verify, args.verbose, args.verbose_all, args.seconds)

if __name__ == "__main__":
    asyncio.run(main())
