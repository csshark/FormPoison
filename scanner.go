package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/fatih/color"
)

func getFileExtension(urlStr string) string {
    parsed, err := url.Parse(urlStr)
    if err != nil {
        return ""
    }
    return path.Ext(parsed.Path)
}

type Vulnerability struct {
	URL         string `json:"url"`
	Line        int    `json:"line"`
	Pattern     string `json:"pattern"`
	CodeSnippet string `json:"code_snippet"`
	Match       string `json:"match"`
	Severity    string `json:"severity"`
}

type ScanReport struct {
	StartURL          string          `json:"start_url"`
	ScannedURLs       int             `json:"scanned_urls"`
	Vulnerabilities   []Vulnerability `json:"vulnerabilities"`
	VulnByType        map[string]int  `json:"vulnerabilities_by_type"`
	ExecutionTime     string          `json:"execution_time"`
	PatternStats      map[string]int  `json:"pattern_statistics"`
	OutputFilename    string          `json:"output_filename"`
}

type Crawler struct {
	visitedURLs    sync.Map
	discoveredURLs chan string
	client         *http.Client
	baseDomain     string
	patterns       map[string]*regexp.Regexp
	maxDepth       int
	maxURLs        int
	urlCount       int
	mu             sync.Mutex
	progress       chan string
}

var javaPatterns = map[string]string{
	"length_validator":    `\.length\s*[<>=!]=\s*\d+`,
	"size_validator":      `\.size\(\)\s*[<>=!]=\s*\d+`,
	"array_index_check":   `\[\s*\w+\s*\]\s*[<>=!]=\s*\d+`,
	"instanceof_check":    `instanceof\s+\w+`,
	"type_casting":        `\(\s*\w+\s*\)\s*\w+`,
	"equals_type_check":   `\.getClass\(\)\.equals\(|\.getClass\(\)\s*==\s*`,
	"null_check":          `==\s*null|!=\s*null`,
	"boundary_check":      `>\s*\d+|<\s*\d+|>=\s*\d+|<=\s*\d+`,
	"regex_validation":    `\.matches\(|Pattern\.compile|\.find\(\)|\.group\(\)`,
}

var owaspPatterns = map[string]string{
	"sql_injection":            `(?i)(SELECT.*FROM.*\$\{|\+.*\w+|executeQuery.*\$\{|\+.*\w+|Statement\.execute|PreparedStatement)`,
	"xss":                      `(?i)(innerHTML\s*=|outerHTML\s*=|document\.write\(|eval\(|\.append\(.*\$\{|alert\(|script\.src)`,
	"path_traversal":           `(?i)(FileInputStream.*\$\{|\+|new File\(.*\$\{|\+|Paths\.get\(.*\$\{|\+|\.\./|\.\.\\)`,
	"command_injection":        `(?i)(Runtime\.getRuntime\(\).exec\(.*\$\{|\+|ProcessBuilder\(.*\$\{|\+|exec\(|system\(|popen\()`,
	"insecure_deserialization": `(?i)(ObjectInputStream|readObject\(|readResolve\(|Serializable|JSON\.parse\(|XMLDecoder)`,
}

func NewCrawler(startURL string, maxDepth, maxURLs int, progress chan string) *Crawler {
	c := &Crawler{
		discoveredURLs: make(chan string, 10000),
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
		maxDepth: maxDepth,
		maxURLs:  maxURLs,
		patterns: make(map[string]*regexp.Regexp),
		progress: progress,
	}

	parsedURL, err := url.Parse(startURL)
	if err != nil {
		log.Fatal("Invalid start URL:", err)
	}
	c.baseDomain = parsedURL.Hostname()

	// Kompiluj wszystkie patterny
	for name, pattern := range javaPatterns {
		c.patterns[name] = regexp.MustCompile(pattern)
	}
	for name, pattern := range owaspPatterns {
		c.patterns[name] = regexp.MustCompile(pattern)
	}

	c.discoveredURLs <- startURL
	return c
}

func (c *Crawler) isSameDomain(urlStr string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return parsed.Hostname() == c.baseDomain
}

func (c *Crawler) shouldVisit(urlStr string, depth int) bool {
	if depth > c.maxDepth {
		return false
	}

	if _, visited := c.visitedURLs.Load(urlStr); visited {
		return false
	}

	if !c.isSameDomain(urlStr) {
		return false
	}

	// only source logic
	ext := path.Ext(urlStr)
	validExtensions := map[string]bool{
		".java": true, ".js": true, ".ts": true,
		".py": true, ".php": true, ".rb": true,
		".go": true, ".c": true, ".cpp": true,
		".html": true, ".jsp": true, ".asp": true,
		".aspx": true, ".cs": true, ".xml": true,
		"": true, // Strony bez rozszerzenia
	}

	return validExtensions[ext]
}

func (c *Crawler) extractURLs(baseURL string, body io.Reader) []string {
	var urls []string
	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		return urls
	}

	base, _ := url.Parse(baseURL)

	doc.Find("a[href], link[href], script[src], img[src], form[action]").Each(func(i int, s *goquery.Selection) {
		var attr string
		if href, exists := s.Attr("href"); exists {
			attr = href
		} else if src, exists := s.Attr("src"); exists {
			attr = src
		} else if action, exists := s.Attr("action"); exists {
			attr = action
		} else {
			return
		}

		absURL, err := base.Parse(attr)
		if err != nil {
			return
		}

		// Normalizuj URL
		absURL.Fragment = ""
		urlStr := absURL.String()

		if c.shouldVisit(urlStr, 0) {
			urls = append(urls, urlStr)
		}
	})

	return urls
}

func (c *Crawler) scanContent(urlStr, content string) []Vulnerability {
	var vulnerabilities []Vulnerability
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		for patternName, regex := range c.patterns {
			matches := regex.FindAllString(line, -1)
			for _, match := range matches {
				severity := "MEDIUM"
				if strings.Contains(patternName, "injection") ||
					strings.Contains(patternName, "deserialization") ||
					strings.Contains(patternName, "xss") {
					severity = "HIGH"
				} else if strings.Contains(patternName, "validator") ||
					strings.Contains(patternName, "check") {
					severity = "LOW"
				}

				// Skip trivial matches
				if len(strings.TrimSpace(match)) < 5 && severity != "HIGH" {
					continue
				}

				vuln := Vulnerability{
					URL:         urlStr,
					Line:        lineNum + 1,
					Pattern:     patternName,
					CodeSnippet: truncateString(strings.TrimSpace(line), 200),
					Match:       truncateString(match, 100),
					Severity:    severity,
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func (c *Crawler) fetchURL(urlStr string) (string, error) {
    req, err := http.NewRequest("GET", urlStr, nil)
    if err != nil {
        return "", err
    }
    
    // Set headers to mimic a real browser
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
    req.Header.Set("Accept-Language", "en-US,en;q=0.5")
    req.Header.Set("Connection", "keep-alive")
    req.Header.Set("Upgrade-Insecure-Requests", "1")

    resp, err := c.client.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("HTTP %d", resp.StatusCode)
    }

    // NEW CONTENT TYPE CHECKING CODE GOES HERE:
    contentType := resp.Header.Get("Content-Type")
    ext := getFileExtension(urlStr)

    // Allow common source code file types regardless of content type
    allowedExtensions := map[string]bool{
        ".js": true, ".java": true, ".py": true, ".php": true, 
        ".rb": true, ".go": true, ".c": true, ".cpp": true,
        ".html": true, ".htm": true, ".jsp": true, ".asp": true,
        ".aspx": true, ".cs": true, ".xml": true, ".json": true,
        ".css": true, ".ts": true,
    }

    // If it's a known source file extension, allow it regardless of content type
    if allowedExtensions[ext] {
        // Proceed with processing - do nothing, just allow it
    } else if !strings.Contains(contentType, "text/html") &&
        !strings.Contains(contentType, "text/plain") &&
        !strings.Contains(contentType, "javascript") &&
        !strings.Contains(contentType, "json") &&
        !strings.Contains(contentType, "xml") {
        return "", fmt.Errorf("unsupported content type: %s for URL %s", contentType, urlStr)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", err
    }

    return string(body), nil
}

func (c *Crawler) CrawlAndScan(workers int, outputFilename string) *ScanReport {
	startTime := time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex

	report := &ScanReport{
		StartURL:       c.baseDomain,
		VulnByType:     make(map[string]int),
		PatternStats:   make(map[string]int),
		OutputFilename: outputFilename,
	}

	vulnChan := make(chan []Vulnerability, 1000)

	// Animation spinner
	spinnerDone := make(chan bool)
	go func() {
		spinnerChars := []string{"|", "/", "-", "\\"}
		i := 0
		for {
			select {
			case <-spinnerDone:
				return
			default:
				c.progress <- fmt.Sprintf("Scanning... %s URLs: %d, Vulnerabilities: %d", 
					spinnerChars[i%len(spinnerChars)], c.urlCount, len(report.Vulnerabilities))
				time.Sleep(100 * time.Millisecond)
				i++
			}
		}
	}()

	// Worker function
	worker := func() {
		defer wg.Done()
		for urlStr := range c.discoveredURLs {
			mu.Lock()
			if c.urlCount >= c.maxURLs {
				mu.Unlock()
				break
			}
			mu.Unlock()

			if _, visited := c.visitedURLs.LoadOrStore(urlStr, true); visited {
				continue
			}

			mu.Lock()
			c.urlCount++
			currentCount := c.urlCount
			mu.Unlock()

			c.progress <- fmt.Sprintf("Scanning URL %d: %s", currentCount, urlStr)

			content, err := c.fetchURL(urlStr)
			if err != nil {
				c.progress <- fmt.Sprintf("Error fetching %s: %v", urlStr, err)
				continue
			}

			vulnerabilities := c.scanContent(urlStr, content)
			if len(vulnerabilities) > 0 {
				vulnChan <- vulnerabilities
				c.progress <- fmt.Sprintf("Found %d vulnerabilities in %s", len(vulnerabilities), urlStr)
			}

			// extract URLs
			if strings.Contains(http.DetectContentType([]byte(content)), "text/html") {
				urls := c.extractURLs(urlStr, strings.NewReader(content))
				for _, newURL := range urls {
					select {
					case c.discoveredURLs <- newURL:
					default:
						// Channel full, skip
					}
				}
			}

			mu.Lock()
			report.ScannedURLs++
			mu.Unlock()

			time.Sleep(50 * time.Millisecond) // Be polite
		}
	}

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}

	// Close vulnChan when all workers are done
	go func() {
		wg.Wait()
		close(vulnChan)
		spinnerDone <- true
	}()

	// Process vulnerabilities
	for vulns := range vulnChan {
		mu.Lock()
		report.Vulnerabilities = append(report.Vulnerabilities, vulns...)
		for _, vuln := range vulns {
			report.VulnByType[vuln.Pattern]++
			report.PatternStats[vuln.Pattern]++
		}
		mu.Unlock()
	}

	report.ExecutionTime = time.Since(startTime).String()
	return report
}

func main() {
	// Setup colored output
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	progress := make(chan string, 100)
	
	// Display progress
	go func() {
		for msg := range progress {
			fmt.Printf("\r%s", msg)
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)

	var startURL, outputFilename string
	var maxURLs, maxDepth, workers int

	if len(os.Args) > 1 {
		startURL = os.Args[1]
		if len(os.Args) > 2 {
			fmt.Sscanf(os.Args[2], "%d", &maxURLs)
		}
		if len(os.Args) > 3 {
			fmt.Sscanf(os.Args[3], "%d", &maxDepth)
		}
		if len(os.Args) > 4 {
			fmt.Sscanf(os.Args[4], "%d", &workers)
		}
		if len(os.Args) > 5 {
			outputFilename = os.Args[5]
		}
	} else if scanner.Scan() {
		input := scanner.Text()
		params := strings.Split(input, "|")

		if len(params) >= 1 {
			startURL = params[0]
		}
		if len(params) >= 2 {
			fmt.Sscanf(params[1], "%d", &maxURLs)
		}
		if len(params) >= 3 {
			fmt.Sscanf(params[2], "%d", &maxDepth)
		}
		if len(params) >= 4 {
			fmt.Sscanf(params[3], "%d", &workers)
		}
		if len(params) >= 5 {
			outputFilename = params[4]
		}
	} else {
		fmt.Println("Usage: echo 'url|max_urls|max_depth|workers|output_filename' | ./scanner")
		fmt.Println("Or: ./scanner <url> [max_urls] [max_depth] [workers] [output_filename]")
		os.Exit(1)
	}

	// Set defaults
	if maxURLs == 0 {
		maxURLs = 100
	}
	if maxDepth == 0 {
		maxDepth = 3
	}
	if workers == 0 {
		workers = 10
	}
	if outputFilename == "" {
		outputFilename = fmt.Sprintf("scan_report_%s_%s.json",
			strings.ReplaceAll(strings.ReplaceAll(startURL, "://", "_"), "/", "_"),
			time.Now().Format("20060102_150405"))
	}

	fmt.Printf("\n%s Starting scan of %s (max URLs: %d, depth: %d, workers: %d, output: %s)\n",
		green("➤"), startURL, maxURLs, maxDepth, workers, outputFilename)

	crawler := NewCrawler(startURL, maxDepth, maxURLs, progress)
	report := crawler.CrawlAndScan(workers, outputFilename)
	close(progress)

	// Generate report
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatal("Error generating JSON report:", err)
	}

	// Write to file
	err = os.WriteFile(outputFilename, reportJSON, 0644)
	if err != nil {
		log.Fatal("Error writing report file:", err)
	}

	// Output filename for Python integration
	fmt.Printf("\n%s\n", outputFilename)

	// Summary
	fmt.Printf("\n%s Scan completed in %s!\n", green("✓"), report.ExecutionTime)
	fmt.Printf("%s URLs scanned: %d\n", yellow("➤"), report.ScannedURLs)
	fmt.Printf("%s Vulnerabilities found: %d\n", yellow("➤"), len(report.Vulnerabilities))

	if len(report.Vulnerabilities) > 0 {
		fmt.Printf("\n%s VULNERABILITY SUMMARY\n", red("⚠"))
		for pattern, count := range report.VulnByType {
			severity := "MEDIUM"
			if strings.Contains(pattern, "injection") ||
				strings.Contains(pattern, "deserialization") ||
				strings.Contains(pattern, "xss") {
				severity = red("HIGH")
			} else if strings.Contains(pattern, "validator") ||
				strings.Contains(pattern, "check") {
				severity = yellow("LOW")
			}
			fmt.Printf("%s %s: %d vulnerabilities\n", severity, pattern, count)
		}
	} else {
		fmt.Printf("\n%s No vulnerabilities found!\n", green("✓"))
	}
}
