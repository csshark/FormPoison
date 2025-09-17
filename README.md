#  <div align ="center"> FormPoison</div>



<p align="center">
  <img src="formpoison.png" width=500px />
</p>

Form-focused Web Application Security Testing Framework based on experience with data validation issues and XSS attacks executed so far (even web applications built on secure frameworks could be vulnerable).
It automates testing common missconfigurations in sanitization in input fields and helps penetration testers find out where to start digging without code review.<p> There is also payload list (custom + AI generated and these frequently used by bounty hunters). </p> <b>Before you start</b>, be aware of many false-positives when running attack. Sometimes web application returns '200 OK' <b>by default</b> and doesn't get injected at all. Run scan, check for CVEs, investigate and then attack. 

## Installation:
<pre><code>git clone https://github.com/csshark/FormPoison.git
cd FormPoison
pip install -r requirements.txt </code></pre>

<sup><sub>ensure you have <b>webdriver-manager</b> installed, to use selenium with Chrome</sub></sup>

## Quick start 

Type <code>python3 formposion.py -h</code> for possible usage and scanner integration instruction. Flags and examples of usage: 

![running inject scans](scan.png)

*Tip: use some payloads manually even if they are not being executed directly on the page, they could work if they are being sent to database and displayed on different endpoints (stored XSS).* 

### Possible optional flags: 
<div align ="center">
  
| flag    | function | type & value(s) | 
| -------- | ------- | ------- | 
| -h --help  | display help message | None |
| -t --threat | select threat type | String: Java, SQL, HTML | 
| --filter | filter payloads by user-defined pattern | String, example: 'xss, script, DROP' |
| --fieldname | specify a fieldname to target directly | String, example: Second Name | 
| -p --payloads | select path to your custom payloads file if necessary | String: /home/user/payloads-folder/payloads.json |
| --cookies | specify user cookie ex. for testing endpoints that require authorization | String, example: 'key1=value1; key2=value2' |
| -v --verbose | enable verbose mode, highly recommended for debugging | None | 
| --verbose-all | advanced output with response body | None |
| --login | enter login+password mode only testing | None |
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

</div>
basic argument: <pre><code>python3 formposion.py yourtargetsite.org</pre></code> <br>
example advanced usage: <pre><code>python3 formpoison.py --cookie "JSESSIONID=9875643544376543211D32" https://www.hackthissite.org/user/login --login -t HTML -s 2</code></pre>

### Scan mode
Scan mode has been extended into JavaScript code scanning and looking for common vectors of code / inproper value injection to bypass some filters. The scanner is separate project integrated into FormPoison by default. It is recommended to run scan firs to identify attack vectors by yourself first. Scanner works for <b>10 minutes max.</b> for smaller apps, to keep lightweight form - this is not autonomus DAST replacement. By default scanner runs with 100 3 10 (100 MaxURLs, 3 MaxDepth, 10 Workers) to suit all the enviroments. However user is allowed to change those values via FormPoison flags. Output file is named *scan_report_[targetURL]_[dateTime].json*. Scanner recognizes ~20 patterns in Java web files and also checks for OWASP Top 10 vulnerabilities.

### payload sources:
- **payloadbox**: https://github.com/payloadbox/sql-injection-payload-list
- **varunsulakhe**: https://github.com/Varunsulakhe/HTML-INJECTOR/blob/main/html-injection-payload.txt
- **custom payloads made by me**

### Expanding payload list:
To make payloads.json more powerfull use *converter.py* to categorize and write payloads in .json format. Create *input.txt* file and store all additional payloads to convert. Remember to convert same type payloads at once, you are hardcoding category.
Example *input.txt* file format:
<pre><code><script>alert('XSS')</script>
  \<samp>XSS\</samp>
  <a href=javascript:alert('XSS')>Click\</a>
    ...and so goes on
</code></pre>

## New functions: 
<ul>
  <li>JavaScript source-code scanner</li>
  <li>Verifying response headers precisely</li>
  <li>Filtering payloads easy way</li>
  <li>Proxy and SSL certificate support</li>
  <li>Multithreading to speed up injecting attemps</li>
  <li>Requests method choice</li>
</ul>

InjOy! 💉
