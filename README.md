#  <div align ="center">💉 FormPoison 💉</div><p><sub><sup><sub>Latest update: 21.10.2025, 20:00 (GMT+2)</sub></sup></sub></p>



<p align="center">
  <img src="formpoison-logo.gif" width=500/>
</p>

Smart form-focused injection Framework based on experience with data validation issues, XSS and SQL attacks executed so far.
The main purpose of the framework is to perform tests that cover the maximum XSS risk for a given application. Please do not treat this tool as a replacement for existing offensive security tools, but rather as a support/companion to them. Cross-Site Scripting is unusual vulnerability and could be found almost randomly with different tools. <b>Before you start</b>, be aware of false-positives when running attack. I did fake results reduction, however web application might return '200 OK' <b>by default</b> and do not get injected at all. Run scan, check for inject CVEs, investigate and then attack. <p><b>Warning:</b> High-intensity tool (~7 req/s). May trigger security alerts. Use responsibly.</p>

## Installation:
<pre><code>git clone https://github.com/csshark/FormPoison.git
cd FormPoison
pip install -r requirements.txt </code></pre>

<sup><sub>ensure you have <b>webdriver-manager</b> installed, to use selenium with Chrome</sub></sup>

## Quick start 
![running inject scans](scan.png)
Please make yourself familiar with the possible flags and how do they work. Payloads file includes over 3500 payloads, so the user must make good use of the filter. 
To begin:<pre><code>python3 formpoison.py -h #show all the flags in order
python3 formation.py targetsite.com</pre></code>
optionally perform deeper front-end code scan:
<pre><code>python3 formpoison targetsite.com --scan
python3 formpoison.py target.com/delivery?startQuery=1 --fieldname "Order Title" -s 4 --filter 'iframe, onload, document.cookie' --verbose</pre></code>
*The command above is gonna be looking for field named "Order Title" (ensure to get field names from DevTools), delay between requests is set to 4 seconds and script is going to filter the payloads from list to these containing only 'iframe', 'onload', 'document.cookie'. Verbose mode is here to visualize results in real time and help with debugging.* 

### Possible optional flags: 
<div align ="center">
  <details><summary><b>Click to expand detailed full flags table.</b></summary>
    
|    flag    | function | type & value(s) | 
| -------- | ------- | ------- | 
| -h --help  | display help message | None |
| -t --threat | select threat type | String: Java, SQL, HTML | 
| --filter | filter payloads by user-defined pattern | String, example: 'xss, script, DROP' |
| --fieldname | specify a fieldname to target directly | String, example: Second Name | 
| --filemode | filename injection mode | None | 
| -p --payloads | select path to your custom payloads file if necessary | String: /home/user/payloads-folder/payloads.json |
| --cookies | specify user cookie ex. for testing endpoints that require authorization | String, example: 'key1=value1; key2=value2' |
| -ua --user-agent | Specify User-Agent or type *random* for shuffling | String, example: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML,like Gecko) Chrome/120.0.0.0 Safari/537.36" |
| -v --verbose | enable verbose mode, highly recommended for debugging | None | 
| --verbose-all | advanced output with response body | None |
| --login | enter login+password mode only testing | None |
| --mXSS | Mutation XSS injections only | None | 
| --brute | <b>Maximum<b> requests speed, might overload target | None OR additional flags | 
| --concurrent | Max concurrent requests for --brute | int: 10-500 (default: 50) | 
| --timeout | Request timeout in seconds for --brute | int: 3-60 (default: 15) | 
| --batch-size | Requests per batch for --brute | int: 10-1000 (default: 100) | 
| --batch-delay | Delay between batches in seconds for --brute | Delay between batches in seconds | int: 0-10 (default: 1) | 
| --retries | Max retries on failure for --brute | int: 1-5 (default: 2) |
| --ssl-cert | use ssl certificate file | String: /home/user/certs/cert.pem | 
| --ssl-key | use ssl private key | String: /home/user/certs/key.pem |
| --ssl-verify | verify ssl certificate | bool: None |
| --proxy | specify proxy for authentication | String, example: http://login:password@proxy.com:8080/ | 
| --method | select request method to force web app confusion | String: GET, POST, PUT, DELETE |  
| -s --seconds | delay between requests to aviod blacklisting | 0-2147483647 (int range but > 0) | 
| --scan | deep scan for .js code and overall web audit | None |
| --max-urls | specify max urls to scan | int range | 
| --max-depth | specify max scan depth | int range | 
| --max-workers | specify number of workers for scanning | int range |
| --waf-bypass | load CDN/WAF evasion payloads | None | 
| --csp-bypass | load CSP bypass payloads | None | 
| --sanitizer-bypass | load HTML sanitizer bypass payloads vs modern JS frameworks (and WordPress) | None | 
| --encoder-bypass | load payloads vs common CMS/frameworks (WordPress, PHP, Python, ASP.NET) | None | 
| --encoding-confusion | load encoding confusion payloads (for GET forms and ASP.NET applications) | None | 
| --size-overflow | load payloads that can lead to overflow or out of bounds | None | 

  </details>
</div>
basic argument: <pre><code>python3 formposion.py yourtargetsite.org</pre></code> <br>
example advanced usage: <pre><code>python3 formpoison.py --cookie "JSESSIONID=9875643544376543211D32" https://www.hackthissite.org/user/login --user-agent "cssharkwashere" --login -t HTML -s 2 --verbose</code></pre>

Please note that not all flags are compatible with each other (e.g., --login does not accept other method values) and you should familiarize yourself with the tool before using it in actual security tests. 

## FormAtion module 
FormAtion is quick form audior, it differs from scan mode in that it performs a quick analysis based on the server's response to a given query. It does not scan the code, nor does it delve into anything other than the input fields themselves. It only analyzes their connections and proposes a ready-made command for FormPoison to execute. Copy + Paste in CLI and now your injection is 20% more likely to be successful.

### Scan mode
Scan mode has been extended into JavaScript code scanning and looking for common vectors of code / inproper value injection to bypass some filters. The scanner is separate project integrated into FormPoison by default. It is recommended to run scan to identify attack vectors by yourself first. Scanner works for <b>10 minutes max.</b> for smaller apps, to keep lightweight form - this is not autonomus DAST replacement. By default scanner runs with 100 3 10 (100 MaxURLs, 3 MaxDepth, 10 Workers) to suit all the enviroments. However user is allowed to change those values via FormPoison flags. Output file is named *scan_report_[targetURL]_[dateTime].json*. Scanner recognizes ~20 patterns in Java web files and also checks for OWASP Top 10 vulnerabilities. Scanner output gives recommendations and points to forms that might be vulnerable (false-positive reduction applied): <div align ="center">![Scanning](scan-output-example.png)</div>


### payload sources:
- **payloadbox**: https://github.com/payloadbox/sql-injection-payload-list
- **varunsulakhe**: https://github.com/Varunsulakhe/HTML-INJECTOR/blob/main/html-injection-payload.txt
- **custom payloads made by me**

### Expanding payload list/Making your own:
To make payloads.json more powerfull use *converter.py* to categorize and write payloads in .json format. Create *input.txt* file and store all additional payloads to convert. Remember to convert same type payloads at once, you are hardcoding category.
Example *input.txt* file format:
<pre><code><script>alert('XSS')</script>
  \<samp>XSS\</samp>
  <a href=javascript:alert('XSS')>Click\</a>
    ...and so goes on
</code></pre>
The user can create their own payloads.json file and does not even need to pay attention to the category if the filtering function is available, and without the *type* flag, FormPoison will go through the entire file anyways.

## Bugs & Issues 
Please note that FormPoison is in the early stages of development, and this is its first release. There may be bugs, which you are encouraged to report so that they can be fixed. 

If you have any ideas on how to improve the tool or have your own implementation, feel free to dig in the source code. Please contact me about contributing.

## New functions: 
<ul>
  <li>Brute mode to speed up requests even more</li>
  <li>Filename XSS testing mode</li>
  <li>Mutation XSS (mXSS) testing mode</li>
  <li>Multithreading to speed up injecting attemps</li>
  <li>Filtering now supported in Login mode</li>
  <li>More Burp-like responses in verbose mode</li>
</ul>

InjOy! 💉
