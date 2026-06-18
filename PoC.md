# Welcome to PoC of FormPoison 

It is nowdays more complicated to deliver new ideas to community, that's why this file has been created. For people who are sceptical about new tools and learning them. Please take a minute and see FormPoison in action!

## Example 1: PortSwigger CSP bypass XSS lab

From the lab description we know we need to bypass CSP somehow. There is one way to do this in FormPoison. 

CSP-Bypass is usually possible via URL param. So we need to provide such flags:
<li><code>--csp-bypass</code> - FormPoison will generate CSP-Bypass payloads.</li>
<li><code>--url-param</code> - we specify which url param to use, you <b>must</b> assign a sample value to the param.</li>
<li><code>--verbose</code> (optional but recommended)</li>
<li><code>--filter alert</code> - most important flag, you specify the keywords that need to be present in payloads you wanna use</li>
<p></p>
So the final command becomes:
<pre><code>python3 formpoison.py https://PORTSWIGGER-LAB.web-security-academy.net/?urlparam=somevalue --url-param --csp-bypass --verbose
</code></pre>
Now we can wait for lab to get solved.
<img width="1854" height="369" alt="image" src="https://github.com/user-attachments/assets/1a4016e6-448e-4b5a-8692-bf541a6402dc" />
simple as that. Obviously FormPoison features include PortSwigger techniques (Web Academy is brilliant source) so this tool should deal good with any labs but also might help you with exam :)  

## Example 2: PortSwigger URL-param-based XSS
Sometimes FormPoison won't be able to deal with fuzzing directly into forms, use <code>--url-param</code> flag whenever it's possible. This will make your efforts <b>extremely</b> shorter. This is not a big surprise most of XSS labs could be solved with this tool, but this is very valuable during exams or with stronger enterprise input sanitizers. 
<img width="1185" height="760" alt="image" src="https://github.com/user-attachments/assets/22270df2-5a4e-4d0f-8c88-47fd58f86b67" />

A lot of flags are implemented for more protected environments please read how do they work in <a href=README.md#Flags>flags</a> section.

## FormPoison is here to assist you
Are you preparing for an exam where open-source tools are allowed? FormPoison is one of them and can help you find your XSS on the web application. 
To use more advanced flags you need to have desired knowledge - for example you need to understand why your payload got blocked.
> FormAtion is not a scanner. It sends one request and performs short analysis of source files. When scanners are forbidden you can use <code>-qs</code> flag with no worries.

## Example 3: DVWA Interactive mode showcase
You can specify which field to target when FormPoison founds it. The best thing is you can provide your own escape sequence before injecting `'poison'` to valid position. In this scenario I used `--interactive` flag with additional information. We use comamnd:
<pre><code>python3 formpoison.py https://pentest-ground.com:4280 --interactive --filter alert --verbose</code></pre>
<img width="1086" height="774" alt="image" src="https://github.com/user-attachments/assets/ecfc4666-f3ef-4a8f-8fcc-933bd3b6e205" />


<p>Now you should see that this tool is not just a script kiddie random tool, but the smart fuzzer only <b>you</b> can control.</p>

## Expand payload list with your favorites
Payloads are stored in .json file so you can specify `-p` flag to specify your own set (check payloads file syntax!). I also created `converter.py` for this simple conversion. You are hardcoding payload category and convert them all into json structured data file. By default there is about 3500 payloads (+ generated ones) included.  
