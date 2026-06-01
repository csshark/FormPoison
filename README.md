# FormPoison <div align ="center"></div><p><sub><sup><sub>Latest update: 01.06.2026, 22:30 (GMT+2)</sub></sup></sub></p>



<p align="center">
  <img src="FormPoison-logo.png" width=500/>
</p>

Smart form-focused injection Framework based on experience with data validation issues, XSS and SQL attacks executed so far.
The main purpose of the framework is to perform tests that cover the maximum XSS risk for a given application. Please do not treat this tool as a replacement for existing offensive security tools, but rather as a support/companion to them.<b>Before you start</b>, be aware of false-positives when running attack. I did fake results reduction, however web application might return '200 OK' <b>by default</b> and do not get injected at all - I couldn't predict all web apps implementations. <p><b>Disclaimer:</b> I do not take repsonisbility for triggering security systems. Use responsible.</p>

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

<p>To make yourself even better with tool, check <a href=PoC.md>PoC</a> of FormPoison! 

### Possible optional flags: 
<div align ="center">
  <details><summary><b>Click to expand detailed full flags table.</b></summary>
    
|    flag    | function | type & value(s) | 
| -------- | ------- | ------- | 
| -h --help  | display help message | None |
| --no-banner | disable banner loading animation | None | 
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
| --batch-delay | Delay between batches in seconds for --brute | int: 0-10 (default: 1) | 
| --retries | Max retries on failure for --brute | int: 1-5 (default: 2) |
| --ssl-cert | use ssl certificate file | String: /home/user/certs/cert.pem | 
| --ssl-key | use ssl private key | String: /home/user/certs/key.pem |
| --ssl-verify | verify ssl certificate | bool: None |
| --proxy | specify proxy for authentication | String, example: http://login:password@proxy.com:8080/ | 
| --method | select request method to force web app confusion | String: GET, POST, PUT, DELETE |  
| -s --seconds | delay between requests to aviod blacklisting | 0-2147483647 (float range but > 0) | 
| --interactive | interactive field injecting mode, user will be asked about every field | String | 
| -qs --check | quick input fields scan/check based on server's response | None | 
| --scan | deep scan for .js code and overall web audit | None |
| --max-urls | specify max urls to scan | int range | 
| --max-depth | specify max scan depth | int range | 
| --max-workers | specify number of workers for scanning | int range |
| --auto-target | perform scan results-based injections | None | 
| --waf-bypass | load CDN/WAF evasion payloads | None | 
| --csp-bypass | load CSP bypass payloads | None | 
| --sanitizer-bypass | load HTML sanitizer bypass payloads vs modern JS frameworks (and WordPress) | None | 
| --encoder-bypass | load payloads vs common CMS/frameworks (WordPress, PHP, Python, ASP.NET) | None | 
| --encoding-confusion | load encoding confusion payloads (for GET forms and ASP.NET applications) | None | 
| --size-overflow | load payloads that can lead to overflow or out of bounds | None | 
| --url-param | analyze and test URL parameters | None | 
| --url param-name | specific URL parameter to test | String | 
| --csp-directive | CSP directive to inject / force | String, example: "script-src-elem" | 
| --csp-value | CSP value to inject | String, example: "unsafe inline" | 

  </details>
</div>
basic argument: <pre><code>python3 formposion.py yourtargetsite.org</pre></code> <br>
example advanced usage: <pre><code>python3 formpoison.py --cookie "JSESSIONID=9875643544376543211D32" https://www.hackthissite.org/user/login --user-agent "cssharkwashere" --login -t HTML -s 2 --verbose</code></pre>

Please note that not all flags are compatible with each other (e.g., --login does not accept other method values) and you should familiarize yourself with the tool before using it in actual security tests. 

## FormAtion module 
FormAtion is quick form audior, it differs from scan mode in that it performs a quick analysis based on the server's response to a given query. It does not scan the code, nor does it delve into anything other than the input fields themselves. It only analyzes their connections and proposes a ready-made command for FormPoison to execute. Copy + Paste in CLI and now your injection is 20% more likely to be successful.
<p><b> Warning:</b> FormAtion does not apply compatibility checks to flags, verify output. </p>

## Interactive mode - take control over injections
The latest powerful feature is interactive mode where user can specify the exact point in input field where payload needs to be injected.
If there is need to inject payloads in specific part of the input, framework is capable of interactive testing mode: <pre><code>python3 formpoison.py [URL] [optional flags] --interactive</code></pre></p> Please keep in mind that your inejection point needs to be specified with quotas like this: <code>'poison'</code> otherwise tool will use it as a static custom user input.
<pre><code>Field 1: admin''poison'
Field 2: diff'poison'iculty</code></pre>
Interactive mode supports a lot of flags and there is still need to provide them for this mode (threat type, filter, delay etc.).

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
Please note that FormPoison is "underground tool" and it's used mainly by people who know this for some reason, so I do not frequently test all features possible. 

If you have any ideas on how to improve the tool or have your own implementation, feel free to dig in the source code. Please contact me about contributing. help me with this! 

## New functions: 
<ul>
  <li>Interactive field injecting has finally been implemented!</li>
  <li>Brute mode to speed up requests even more</li>
  <li>Multithreading to speed up injecting attemps</li>
  <li>Filtering now supported in Login mode</li>
  <li>CSP bypass methods fully implemented</li>
  <li>Reflection validator has been optimized</li>
</ul>

InjOy! 💉
