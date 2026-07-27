<table border="1" cellspacing="0" cellpadding="6">
  <thead>
    <tr>
      <th>Flag</th>
      <th>Description</th>
      <th>Example value / usage</th>
    </tr>
  </thead>
  <tbody>
    <tr><td><code>url</code></td><td>Target form or page URL to test (required argument).</td><td><code>https://example.com/login</code></td></tr>
    <tr><td><code>--no-banner</code></td><td>Skip the startup banner animation.</td><td><code>--no-banner</code></td></tr>
    <tr><td><code>--interactive</code></td><td>Enable interactive mode for greater control over testing.</td><td><code>--interactive</code></td></tr>
    <tr><td><code>--check</code>, <code>-qs</code></td><td>Perform a quick pre-scan analysis before running tests.</td><td><code>--check</code></td></tr>
    <tr><td><code>--scan</code></td><td>Perform a quick crawl of the target website.</td><td><code>--scan</code></td></tr>
    <tr><td><code>--max-urls</code></td><td>Maximum number of URLs to crawl.</td><td><code>--max-urls 250</code></td></tr>
    <tr><td><code>--max-depth</code></td><td>Maximum crawl depth.</td><td><code>--max-depth 5</code></td></tr>
    <tr><td><code>--workers</code></td><td>Number of concurrent crawler workers.</td><td><code>--workers 20</code></td></tr>
    <tr><td><code>--auto-target</code></td><td>Automatically generate targeted payloads based on crawler results.</td><td><code>--auto-target</code></td></tr>
    <tr><td><code>-t</code>, <code>--threat</code></td><td>Threat category to test.</td><td><code>--threat HTML</code></td></tr>
    <tr><td><code>-p</code>, <code>--payloads</code></td><td>Path to the custom JSON payload file.</td><td><code>--payloads custom_payloads.json</code></td></tr>
    <tr><td><code>--cookies</code></td><td>Send custom HTTP cookies with requests.</td><td><code>--cookies "session=abc123; theme=dark"</code></td></tr>
    <tr><td><code>-ua</code>, <code>--user-agent</code></td><td>Specify a custom User-Agent or use <code>random</code>.</td><td><code>--user-agent random</code></td></tr>
    <tr><td><code>--proxy</code></td><td>Route requests through an HTTP proxy.</td><td><code>--proxy http://127.0.0.1:8080</code></td></tr>
    <tr><td><code>--ssl-cert</code></td><td>Path to the client SSL certificate.</td><td><code>--ssl-cert cert.pem</code></td></tr>
    <tr><td><code>--ssl-key</code></td><td>Path to the client SSL private key.</td><td><code>--ssl-key key.pem</code></td></tr>
    <tr><td><code>--ssl-verify</code></td><td>Enable SSL certificate verification.</td><td><code>--ssl-verify</code></td></tr>
    <tr><td><code>--mXSS</code></td><td>Test for Mutation XSS (mXSS) vulnerabilities.</td><td><code>--mXSS</code></td></tr>
    <tr><td><code>--brute</code></td><td>Enable maximum-speed testing mode.</td><td><code>--brute</code></td></tr>
    <tr><td><code>--concurrent</code></td><td>Maximum number of concurrent HTTP requests.</td><td><code>--concurrent 100</code></td></tr>
    <tr><td><code>--timeout</code></td><td>Request timeout in seconds.</td><td><code>--timeout 30</code></td></tr>
    <tr><td><code>--batch-size</code></td><td>Number of requests per batch.</td><td><code>--batch-size 200</code></td></tr>
    <tr><td><code>--batch-delay</code></td><td>Delay between request batches (seconds).</td><td><code>--batch-delay 2</code></td></tr>
    <tr><td><code>--retries</code></td><td>Maximum number of retries for failed requests.</td><td><code>--retries 5</code></td></tr>
    <tr><td><code>--method</code></td><td>HTTP method used for testing.</td><td><code>--method POST</code></td></tr>
    <tr><td><code>--filter</code></td><td>Filter payloads by one or more patterns.</td><td><code>--filter "&lt;script&gt;,onclick"</code></td></tr>
    <tr><td><code>--login</code></td><td>Enable login form testing for username and password fields.</td><td><code>--login</code></td></tr>
    <tr><td><code>--verbose</code></td><td>Enable verbose output.</td><td><code>--verbose</code></td></tr>
    <tr><td><code>--verbose-all</code></td><td>Enable verbose output including response bodies.</td><td><code>--verbose-all</code></td></tr>
    <tr><td><code>--fieldname</code></td><td>Test only the specified input field.</td><td><code>--fieldname username</code></td></tr>
    <tr><td><code>--filemode</code></td><td>Test filename-based XSS in file upload forms.</td><td><code>--filemode</code></td></tr>
    <tr><td><code>-s</code>, <code>--seconds</code></td><td>Delay between requests (seconds).</td><td><code>--seconds 0.5</code></td></tr>
    <tr><td><code>--waf-bypass</code></td><td>Generate payloads designed to bypass WAF protections.</td><td><code>--waf-bypass</code></td></tr>
    <tr><td><code>--csp-bypass</code></td><td>Generate payloads targeting CSP bypass techniques.Recommended to use with <code>--url-param</code> flag</td><td><code>--csp-bypass</code></td></tr>
    <tr><td><code>--sanitizer-bypass</code></td><td>Generate payloads to test HTML sanitizer bypasses.</td><td><code>--sanitizer-bypass</code></td></tr>
    <tr><td><code>--encoder-bypass</code></td><td>Generate payloads using encoding bypass techniques.</td><td><code>--encoder-bypass</code></td></tr>
    <tr><td><code>--encoding-confusion</code></td><td>Generate payloads exploiting character encoding ambiguities.</td><td><code>--encoding-confusion</code></td></tr>
    <tr><td><code>--size-overflow</code></td><td>Generate oversized payloads to test input size limits.</td><td><code>--size-overflow</code></td></tr>
    <tr><td><code>--url-param</code></td><td>Analyze and test URL query parameters.</td><td><code>--url-param</code></td></tr>
    <tr><td><code>--url-param-name</code></td><td>Target a specific URL query parameter.</td><td><code>--url-param-name search</code></td></tr>
    <tr><td><code>--csp-directive</code></td><td>Specify the CSP directive to target.</td><td><code>--csp-directive script-src</code></td></tr>
    <tr><td><code>--csp-value</code></td><td>Specify the CSP value to inject.</td><td><code>--csp-value "'unsafe-inline'"</code></td></tr>
  </tbody>
</table>
