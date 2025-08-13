# FormPoison 📄💉
Form Input Fuzzing Framework made with Python based on my experience with data validation issues and XSS attacks executed by me.
It automates testing common missconfigurations in sanitization in input fields.<p> There is also payload list (my own + AI generated and these frequently used by bounty hunters). 

## Installation:
<pre><code>git clone https://github.com/csshark/FormPoison.git
cd FormPoison
pip install -r requirements.txt </code></pre>

<sup><sub>ensure you have <b>webdriver-manager</b> installed, to use selenium with Chrome</sub></sup>

## Quick start 

Type <code>python3 formposion.py -h</code> for possible usage. Flags and examples of usage: 

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
| --ssl-verify | verify ssl certificate | bool: True/False |
| --proxy | specify proxy for authentication | String, example: http://login:password@proxy.com:8080/ | 
| --method | select request method | String: GET, POST, PUT, DELETE |  
| -s --seconds | delay between requests to aviod blacklisting | 0-2147483647 (int range but > 0) | 

</div>
basic argument: <pre><code>python3 formposion.py yourtargetsite.org</pre></code> <br>
example advanced usage: <pre><code>python3 formpoison.py --cookie "JSESSIONID=9875643544376543211D32" https://www.hackthissite.org/user/login --login -t HTML -s 2</code></pre>

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
  <li>Verifying response headers precisely</li>
  <li>Filtering payloads easy way</li>
  <li>Proxy and SSL certificate support</li>
  <li>Multithreading to speed up injecting attemps</li>
  <li>Requests method choice</li>
</ul>

InjOy! 💉
