# FormPoison <div align ="center"></div><p><sub><sup><sub>Latest update: 15.06.2026, 22:25 (GMT+2)</sub></sup></sub></p>

<p align="center">
  <img src="FormPoison-logo.png" width=500/>
</p>

Smart form-focused XSS framework built from practical experience with data validation flawsin real-world web application testing.

The primary goal of FormPoison is to maximize XSS attack surface coverage by focusing on user-controlled forms, reflected inputs, frontend behavior and validation weaknesses. While the framework includes payloads for SQL Injection **XSS discovery and exploitation remains its core purpose**.

---

## Installation

<pre><code>git clone https://github.com/csshark/FormPoison.git
cd FormPoison

pip install -r requirements.txt
pip install webdriver-manager</code></pre>
---

## Quick Start

Basic attack:

<pre><code>python3 formpoison.py https://target.com --verbose</code></pre>

Frontend deep reconnaissance (requires GoScanner compilation):

<pre><code>python3 formpoison.py https://target.com --scan</code></pre>

Quick reflection discovery:

<pre><code>python3 formpoison.py https://target.com -qs</code></pre>

Target a specific field:

<pre><code>python3 formpoison.py \
https://target.com/contact \
--fieldname "Message" \
--filter "script,onerror,svg" \
--verbose
</code></pre>
---

## Features

- XSS-focused payload engine
- Reflection detection and validation
- Form reconnaissance (FormAtion)
- Frontend discovery
- DOM sink identification
- Interactive injection mode
- Login and authenticated testing
- CSP bypass
- WAF bypass
- Mutation XSS payloads
- Encoding confusion payloads
- High-speed brute mode

---

## Useful Options
<div align="center">
  
| Flag | Description |
|------|-------------|
| --scan | Frontend reconnaissance |
| --url-param | Target an URL parameter | 
| --csp-bypass | Generate and use CSP bypass payloads | 
| -qs | Quick reflection discovery |
| --interactive | Manual injection placement |
| --fieldname | Target a specific field |
| --filter | Use payloads matching keyword |
| --cookies | Authenticated testing |
| --login | Login workflow testing |
| --verbose | Real-time output |
| --brute | Maximum throughput mode |
</div>
Display all available options:

<pre><code>python3 formpoison.py -h</code></pre>

---

## Examples

Authentication required:

<pre><code>python3 formpoison.py https://target.com/profile --cookies "SESSIONID=value"</code></pre>

Interactive mode:

<pre><code>python3 formpoison.py https://target.com --interactive</code></pre>

Custom payloads file:

<pre><code>python3 formpoison.py https://target.com -p payloads.json</code></pre>

---

## Contributing

Contributions are welcome through Issues and Pull Requests.

---

**InjOy! 💉**
