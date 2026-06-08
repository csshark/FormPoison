# Welcome to PoC of FormPoison 

FormPoison can solve PortSwigger PRACTITIONER marked labs and has been tested in that field. 

## Example 1: PortSwigger CSP bypass XSS lab

From the lab description we know we need to bypass CSP somehow. There is one way to do this in FormPoison. 

CSP-Bypass is usually possible via URL param. So we need to provide such flags:
<li>--csp-bypass</li>
<li>--url-param</li>
<li>--verbose (optional but recommended)</li>

So the final command becomes:
<pre><code>python3 formpoison.py https://PORTSWIGGER-LAB.web-security-academy.net --url-param --csp-bypass --verbose
</code></pre>
Now we can wait for lab to get solved.
<img width="1854" height="369" alt="image" src="https://github.com/user-attachments/assets/1a4016e6-448e-4b5a-8692-bf541a6402dc" />
simple as that. Obviously FormPoison features include PortSwigger techniques (Web Academy is brilliant source) so this tool should deal good with any labs but also might help you with exam :)  

## FormPoison is here to assist you
Are you preparing for an exam where open-source tools are allowed? FormPoison is one of them and can help you find your XSS on the web application. 
To use more advanced flags you need to have desired knowledge - for example you need to understand why your payload got blocked.
> FormAtion is not< a scanner. It sends one request and performs short analysis of source files.

