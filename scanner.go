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
)

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
	"sql_injection":            `SELECT.*FROM.*\$\{|\+.*\w+|executeQuery.*\$\{|\+.*\w+`,
	"xss":                      `innerHTML\s*=|outerHTML\s*=|document\.write\(|eval\(|\.append\(.*\$\{`,
	"path_traversal":           `FileInputStream.*\$\{|\+|new File\(.*\$\{|\+|Paths\.get\(.*\$\{|\+`,
	"command_injection":        `Runtime\.getRuntime\(\).exec\(.*\$\{|\+|ProcessBuilder\(.*\$\{|\+`,
	"insecure_deserialization": `ObjectInputStream|readObject\(|readResolve\(|Serializable|JSON\.parse\(|XMLDecoder`,
}

func NewCrawler(startURL string, maxDepth, maxURLs int) *Crawler {
	c := &Crawler{
		discoveredURLs: make(chan string, 1000),
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     30 * time.Second,
			},
		},
		maxDepth: maxDepth,
		maxURLs:  maxURLs,
		patterns: make(map[string]*regexp.Regexp),
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

	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}

		absURL, err := base.Parse(href)
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
					strings.Contains(patternName, "deserialization") {
						severity = "HIGH"
					}

					vuln := Vulnerability{
						URL:         urlStr,
						Line:        lineNum + 1,
						Pattern:     patternName,
						CodeSnippet: strings.TrimSpace(line),
						Match:       match,
						Severity:    severity,
					}
					vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities
}

func (c *Crawler) fetchURL(urlStr string) (string, error) {
	resp, err := c.client.Get(urlStr)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") &&
		!strings.Contains(contentType, "text/plain") &&
		!strings.Contains(contentType, "application/javascript") {
			return "", fmt.Errorf("unsupported content type: %s", contentType)
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

	vulnChan := make(chan []Vulnerability, 100)
	urlCount := 0

	// Worker function
	worker := func() {
		defer wg.Done()
		for urlStr := range c.discoveredURLs {
			if urlCount >= c.maxURLs {
				break
			}

			if _, visited := c.visitedURLs.LoadOrStore(urlStr, true); visited {
				continue
			}

			mu.Lock()
			urlCount++
			mu.Unlock()

			content, err := c.fetchURL(urlStr)
			if err != nil {
				continue
			}


			vulnerabilities := c.scanContent(urlStr, content)
			if len(vulnerabilities) > 0 {
				vulnChan <- vulnerabilities
			}

			// extract URLs
			if strings.Contains(http.DetectContentType([]byte(content)), "text/html") {
				urls := c.extractURLs(urlStr, strings.NewReader(content))
				for _, newURL := range urls {
					select {
						case c.discoveredURLs <- newURL:
						default:

					}
				}
			}

			mu.Lock()
			report.ScannedURLs++
			mu.Unlock()


			time.Sleep(100 * time.Millisecond)
		}
	}


	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}


	go func() {
		wg.Wait()
		close(vulnChan)
	}()


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
			fmt.Sscanf(params[3], "%d", &maxDepth)
		}
		if len(params) >= 4 {
			fmt.Sscanf(params[4], "%d", &workers)
		}
		if len(params) >= 5 {
			outputFilename = params[5]
		}
	} else {
		fmt.Println("Usage: echo 'url|max_urls|max_depth|workers|output_filename' | ./scanner")
		fmt.Println("Or: ./scanner <url> [max_urls] [max_depth] [workers] [output_filename]")
		os.Exit(1)
	}

	// go default
	if maxURLs == 0 {
		maxURLs = 50
	}
	if maxDepth == 0 {
		maxDepth = 2
	}
	if workers == 0 {
		workers = 5
	}
	if outputFilename == "" {
		outputFilename = fmt.Sprintf("scan_report_%s_%s.json",
					     strings.ReplaceAll(startURL, "://", "_"),
					     time.Now().Format("20060102_150405"))
	}

	log.Printf("Starting scan of %s (max URLs: %d, depth: %d, workers: %d, output: %s)",
		   startURL, maxURLs, maxDepth, workers, outputFilename)

	crawler := NewCrawler(startURL, maxDepth, maxURLs)
	report := crawler.CrawlAndScan(workers, outputFilename)

	// raport gen
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatal("Error generating JSON report:", err)
	}

	// output to file
	err = os.WriteFile(outputFilename, reportJSON, 0644)
	if err != nil {
		log.Fatal("Error writing report file:", err)
	}

	// stdout for Python
	fmt.Println(outputFilename)

	log.Printf("Scan completed! Scanned %d URLs, found %d vulnerabilities",
		   report.ScannedURLs, len(report.Vulnerabilities))
	log.Printf("Report saved to: %s", outputFilename)

	if len(report.Vulnerabilities) > 0 {
		log.Println("\n=== VULNERABILITY SUMMARY ===")
		for pattern, count := range report.VulnByType {
			log.Printf("%s: %d vulnerabilities", pattern, count)
		}
	} else {
		log.Println("No vulnerabilities found!")
	}
}
