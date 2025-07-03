# FormPoison 📄💉
Form Input Fuzzing Framework made with Python based on my experience with data validation issues and XSS attacks executed by me.
It automates testing common missconfigurations in sanitization in input fields.<p> There is also payload list (my own + AI generated and these frequently used by bounty hunters). 

## Installation:
Clone repo:
<pre><code>git clone https://github.com/csshark/FormPoison.git</code></pre>
Try to run:
<pre><code>python3 formpoison.py [url]</code></pre>
Install missing libraries and you are ready to go!

## Quick start 

Type <code>python3 formposion.py -h</code> for possible usage. Using this tool is very easy so I gave up on flags table this time.

![running inject scans](scan.png)

*Tip: use some payloads even if they are not being executed directly on the page, they could work if they are being displayed on different endpoints (stored XSS).* 

### payload sources:
- **payloadbox**: https://github.com/payloadbox/sql-injection-payload-list
- **varunsulakhe**: https://github.com/Varunsulakhe/HTML-INJECTOR/blob/main/html-injection-payload.txt
- **custom payloads made by me**

### Expanding payload list:
To make payloads.json more powerfull use *converter.py* to categorize and write payloads in .json format. Create *input.txt* file and store all additional payloads to convert.
