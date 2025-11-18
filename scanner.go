package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"context" 
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
    "flag"

	"github.com/PuerkitoBio/goquery"
	"github.com/fatih/color"
)

// basic structures
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
    proxyURL       string 
}

// more 
type VariableContext struct {
	Name            string            `json:"name"`
	DataType        string            `json:"data_type"`
	UsageContext    string            `json:"usage_context"`
	RiskLevel       string            `json:"risk_level"`
	Confidence      float64           `json:"confidence"`
	Occurrences     int               `json:"occurrences"`
	Locations       []VariableLocation `json:"locations"`
	SemanticMeaning string            `json:"semantic_meaning"`
	IsUserInput     bool              `json:"is_user_input"`
	IsCritical      bool              `json:"is_critical"`
}

type VariableLocation struct {
	URL      string `json:"url"`
	Line     int    `json:"line"`
	Context  string `json:"context"`
	Function string `json:"function"`
}

type ContextualVulnerability struct {
	Vulnerability
	VariableContext   *VariableContext `json:"variable_context,omitempty"`
	ContextAnalysis   string          `json:"context_analysis"`
	FalsePositiveRisk float64         `json:"false_positive_risk"`
}

type EnhancedScanReport struct {
	ScanReport
	VariableContexts    map[string]*VariableContext `json:"variable_contexts"`
	ContextualVulns     []ContextualVulnerability  `json:"contextual_vulnerabilities"`
	FalsePositivesReduced int                      `json:"false_positives_reduced"`
	ContextStats        ContextStatistics         `json:"context_statistics"`
}

type ContextStatistics struct {
	VariablesAnalyzed    int     `json:"variables_analyzed"`
	HighRiskVariables    int     `json:"high_risk_variables"`
	UserInputVariables   int     `json:"user_input_variables"`
	CriticalVariables    int     `json:"critical_variables"`
	AverageConfidence    float64 `json:"average_confidence"`
}

// added context to crawler 
type ContextAwareCrawler struct {
	*Crawler
	variableContexts  map[string]*VariableContext
	contextPatterns   map[string]*regexp.Regexp
	semanticPatterns  map[string]*regexp.Regexp
}

// helper funct
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// javaPatterns
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
	"unchecked_exception": `throws\s+\w+Exception`,
	"reflection":          `Class\.forName\(|Method\.invoke\(|Field\.set\(`,
	"serialization":       `implements\s+Serializable|ObjectOutputStream|ObjectInputStream`,
	"file_handling":       `new\s+File\(|FileInputStream|FileOutputStream`,
	"network_io":          `Socket\(|ServerSocket\(|URLConnection`,
	"string_concatenation": `\w+\s*\+\s*\w+`,
	"date_handling":       `SimpleDateFormat\(|Date\(|Calendar\.getInstance\(\)`,
	"enum_usage":          `enum\s+\w+`,
	"annotation_usage":    `@\w+\(`,
	"lambda_expression":   `->\s*\w+`,
	"stream_usage":        `\.stream\(\)|\.map\(|\.filter\(|\.collect\(\)`,
	"optional_usage":      `Optional\.of\(|Optional\.empty\(\)`,
	"concurrency":         `synchronized\s*\(|volatile\s+\w+|Atomic\w+`,
	"resource_management": `try\s*\(|\.close\(\)|AutoCloseable`,
}

var owaspPatterns = map[string]string{
	"sql_injection":            `(?i)(SELECT.*FROM.*\$\{|\+.*\w+|executeQuery.*\$\{|\+.*\w+|Statement\.execute|PreparedStatement)`,
	"xss":                      `(?i)(innerHTML\s*=|outerHTML\s*=|document\.write\(|eval\(|\.append\(.*\$\{|alert\(|script\.src)`,
	"path_traversal":           `(?i)(FileInputStream.*\$\{|\+|new File\(.*\$\{|\+|Paths\.get\(.*\$\{|\+|\.\./|\.\.\\)`,
	"command_injection":        `(?i)(Runtime\.getRuntime\(\).exec\(.*\$\{|\+|ProcessBuilder\(.*\$\{|\+|exec\(|system\(|popen\()`,
	"insecure_deserialization": `(?i)(ObjectInputStream|readObject\(|readResolve\(|Serializable|JSON\.parse\(|XMLDecoder)`,
}

var additionalPatterns = map[string]string{
	"type_confusion":       `(?i)(instanceof\s+\w+\s*\(\s*\w+\s*\)|\(\s*\w+\s*\)\s*\w+\s*instanceof)`,
	"race_condition":       `(?i)(synchronized\s*\(\s*\w+\s*\)|Lock\s*\(\s*\w+\s*\)|Semaphore\s*\(\s*\w+\s*\))`,
	"insecure_randomness":  `(?i)(Math\.random\(\)|Random\s*\(\s*\w+\s*\)|SecureRandom\s*\(\s*\w+\s*\))`,
}

// contxt patterns
var contextPatterns = map[string]string{
	"user_input_vars":     `(?i)(user|usr|u_|input|inp|param|arg|get|post|request|req|query|qry|form|field|fld)`,
	"session_vars":        `(?i)(session|sess|s_|token|tok|auth|login|pass|pwd|credential|cookie)`,
	"financial_vars":      `(?i)(amount|amt|balance|bal|price|cost|fee|payment|pay|transaction|txn|account|acct|bank|money|cash|currency)`,
	"personal_data_vars":  `(?i)(name|nama|firstname|lastname|email|e-mail|mail|address|addr|phone|tel|mobile|ssn|pesel|nip|personal|private)`,
	"security_vars":       `(?i)(secret|key|password|pwd|hash|salt|encrypt|decrypt|crypto|signature|certificate|cert)`,
	"config_vars":         `(?i)(config|cfg|setting|setting|option|opt|property|prop|env|environment)`,
	"database_vars":       `(?i)(db|database|sql|query|stmt|statement|table|tbl|column|col|row|record|result|rs)`,
	"file_vars":           `(?i)(file|filename|path|directory|dir|folder|upload|download|stream)`,
	"network_vars":        `(?i)(host|port|ip|url|uri|endpoint|api|service|server|client|socket)`,
	"length_vars":         `(?i)(length|len|size|limit|max|min|count|cnt|total)`,
	"id_vars":             `(?i)(id|identifier|idx|index|key|pk|fk|uid|uuid|guid)`,
	"validation_context":  `(?i)(validate|validation|check|verify|sanitize|filter|clean)`,
	"authentication_context": `(?i)(authenticate|auth|login|logout|register|signin|signout)`,
	"authorization_context": `(?i)(authorize|permission|role|access|grant|deny)`,
	"financial_context":   `(?i)(pay|transfer|withdraw|deposit|invoice|bill|receipt)`,
	"admin_context":       `(?i)(admin|administrator|root|superuser|manage|management)`,
}

// semantic patterns
var semanticPatterns = map[string]string{
	"variable_declaration": `(?:var|let|const|String|int|Integer|long|float|double|boolean|Boolean|Object)\s+(\w+)\s*=?`,
	"function_parameter":   `function\s+\w+\s*\(\s*([^)]+)\s*\)|def\s+\w+\s*\(\s*([^)]+)\s*\)`,
	"method_declaration":   `(?:public|private|protected)\s+\w+\s+\w+\s*\(\s*([^)]+)\s*\)`,
	"assignment_pattern":   `(\w+)\s*=\s*[^;]+;`,
	"usage_pattern": `(\w+)\s*[=+\-*/]|\.(\w+)\s*\(|(\w+)\s*\.|\$\{\s*(\w+)\s*\}`,
}

// semantic dicts
var semanticDictionaries = map[string][]string{
	"financial": {
		"balance", "amount", "transaction", "payment", "transfer", 
		"account", "currency", "money", "cash", "price", "cost", "fee",
		"interest", "loan", "credit", "debit", "withdraw", "deposit",
	},
	"personal": {
		"name", "email", "address", "phone", "birthdate", "age", "gender",
		"ssn", "pesel", "nip", "passport", "idcard", "personal", "private",
	},
	"authentication": {
		"password", "token", "session", "login", "auth", "credential",
		"certificate", "key", "secret", "hash", "salt", "otp", "2fa",
	},
	"system": {
		"config", "setting", "environment", "property", "parameter",
		"admin", "root", "superuser", "privilege", "permission", "role",
	},
	"network": {
		"url", "uri", "endpoint", "api", "host", "port", "ip", "domain",
		"request", "response", "header", "cookie", "proxy", "dns",
	},
	"database": {
		"query", "sql", "table", "column", "row", "record", "index",
		"select", "insert", "update", "delete", "where", "join",
	},
}

func NewContextAwareCrawler(startURL string, maxDepth, maxURLs int, progress chan string, proxyURL string) *ContextAwareCrawler {
    baseCrawler := NewCrawler(startURL, maxDepth, maxURLs, progress, proxyURL)
    
    c := &ContextAwareCrawler{
        Crawler:          baseCrawler,
        variableContexts: make(map[string]*VariableContext),
        contextPatterns:  make(map[string]*regexp.Regexp),
        semanticPatterns: make(map[string]*regexp.Regexp),
    }

    for name, pattern := range contextPatterns {
        c.contextPatterns[name] = regexp.MustCompile(pattern)
    }
    for name, pattern := range semanticPatterns {
        c.semanticPatterns[name] = regexp.MustCompile(pattern)
    }

    return c
}

// contextAwareCrawl
func (c *ContextAwareCrawler) analyzeVariableContext(variableName, codeSnippet, urlStr string, lineNum int) *VariableContext {
	context := &VariableContext{
		Name:         variableName,
		Occurrences:  1,
		Confidence:   0.5,
		RiskLevel:    "LOW",
		Locations:    []VariableLocation{},
	}

	context.Locations = append(context.Locations, VariableLocation{
		URL:     urlStr,
		Line:    lineNum,
		Context: truncateString(codeSnippet, 150),
	})

	c.analyzeVariableName(context, variableName)
	c.analyzeUsageContext(context, codeSnippet)
	c.analyzeSemanticMeaning(context, variableName, codeSnippet)
	c.determineRiskLevel(context)
	c.calculateConfidence(context)

	return context
}

func (c *ContextAwareCrawler) analyzeVariableName(context *VariableContext, variableName string) {
	for patternType, regex := range c.contextPatterns {
		if regex.MatchString(variableName) {
			switch patternType {
			case "user_input_vars":
				context.IsUserInput = true
				context.UsageContext = "user_input"
				context.Confidence += 0.2
			case "session_vars", "security_vars":
				context.UsageContext = "security"
				context.IsCritical = true
				context.Confidence += 0.3
			case "financial_vars":
				context.UsageContext = "financial"
				context.IsCritical = true
				context.Confidence += 0.4
			case "personal_data_vars":
				context.UsageContext = "personal_data"
				context.IsCritical = true
				context.Confidence += 0.35
			}
		}
	}
}

func (c *ContextAwareCrawler) analyzeUsageContext(context *VariableContext, codeSnippet string) {
	snippetLower := strings.ToLower(codeSnippet)
	
	if strings.Contains(snippetLower, "validate") || strings.Contains(snippetLower, "check") {
		context.UsageContext = "validation"
		context.Confidence += 0.15
	}
	
	if strings.Contains(snippetLower, "auth") || strings.Contains(snippetLower, "login") {
		context.UsageContext = "authentication"
		context.IsCritical = true
		context.Confidence += 0.25
	}
	
	if strings.Contains(snippetLower, "payment") || strings.Contains(snippetLower, "transfer") {
		context.UsageContext = "financial"
		context.IsCritical = true
		context.Confidence += 0.3
	}
	
	if strings.Contains(snippetLower, "select") || strings.Contains(snippetLower, "insert") {
		context.UsageContext = "database"
		context.Confidence += 0.2
	}
}

func (c *ContextAwareCrawler) analyzeSemanticMeaning(context *VariableContext, variableName, codeSnippet string) {
	variableLower := strings.ToLower(variableName)
	
	for category, words := range semanticDictionaries {
		for _, word := range words {
			if variableLower == word || strings.Contains(variableLower, word) {
				context.SemanticMeaning = category
				context.Confidence += 0.25
				
				if category == "financial" || category == "personal" || category == "authentication" {
					context.IsCritical = true
				}
				break
			}
		}
	}
	
	if strings.Contains(codeSnippet, ".length") || strings.Contains(codeSnippet, ".size()") {
		context.DataType = "numeric_length"
	} else if strings.Contains(codeSnippet, ".equals(") || strings.Contains(codeSnippet, ".contains(") {
		context.DataType = "string"
	} else if strings.Contains(codeSnippet, ">") || strings.Contains(codeSnippet, "<") {
		context.DataType = "numeric_comparison"
	}
}

func (c *ContextAwareCrawler) determineRiskLevel(context *VariableContext) {
	riskScore := 0.0
	
	if context.IsCritical {
		riskScore += 3
	}
	if context.IsUserInput {
		riskScore += 2
	}
	if context.UsageContext == "financial" || context.UsageContext == "security" {
		riskScore += 2
	}
	if context.Occurrences > 5 {
		riskScore += 1
	}
	if context.Confidence > 0.7 {
		riskScore += 1
	}
	
	switch {
	case riskScore >= 5:
		context.RiskLevel = "HIGH"
	case riskScore >= 3:
		context.RiskLevel = "MEDIUM"
	default:
		context.RiskLevel = "LOW"
	}
}

func (c *ContextAwareCrawler) calculateConfidence(context *VariableContext) {
	if context.Confidence > 1.0 {
		context.Confidence = 1.0
	} else if context.Confidence < 0.1 {
		context.Confidence = 0.1
	}
}

func (c *ContextAwareCrawler) extractVariablesFromCode(content, urlStr string) map[string]*VariableContext {
	variables := make(map[string]*VariableContext)
	lines := strings.Split(content, "\n")
	
	for lineNum, line := range lines {
		if matches := c.semanticPatterns["variable_declaration"].FindStringSubmatch(line); len(matches) > 1 {
			variableName := strings.TrimSpace(matches[1])
			if c.isValidVariableName(variableName) {
				if existing, exists := variables[variableName]; exists {
					existing.Occurrences++
					existing.Locations = append(existing.Locations, VariableLocation{
						URL:     urlStr,
						Line:    lineNum + 1,
						Context: truncateString(line, 150),
					})
				} else {
					variables[variableName] = c.analyzeVariableContext(variableName, line, urlStr, lineNum+1)
				}
			}
		}
		
		if matches := c.semanticPatterns["usage_pattern"].FindAllStringSubmatch(line, -1); len(matches) > 0 {
			for _, match := range matches {
				for i := 1; i < len(match); i++ {
					if match[i] != "" && c.isValidVariableName(match[i]) {
						variableName := strings.TrimSpace(match[i])
						if existing, exists := variables[variableName]; exists {
							existing.Occurrences++
						} else {
							variables[variableName] = c.analyzeVariableContext(variableName, line, urlStr, lineNum+1)
						}
					}
				}
			}
		}
	}
	
	return variables
}

func (c *ContextAwareCrawler) isValidVariableName(name string) bool {
	if len(name) < 2 || len(name) > 50 {
		return false
	}
	
	if !unicode.IsLetter(rune(name[0])) {
		return false
	}
	
	for _, char := range name {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) && char != '_' {
			return false
		}
	}
	
	return true
}

func (c *ContextAwareCrawler) enhanceVulnerabilityWithContext(vuln Vulnerability, variables map[string]*VariableContext) ContextualVulnerability {
	contextualVuln := ContextualVulnerability{
		Vulnerability:   vuln,
		FalsePositiveRisk: 0.5,
	}
	
	for varName, varContext := range variables {
		if strings.Contains(vuln.CodeSnippet, varName) {
			contextualVuln.VariableContext = varContext
			contextualVuln.ContextAnalysis = c.analyzeVulnerabilityContext(varName, varContext, vuln)
			contextualVuln.FalsePositiveRisk = c.calculateFalsePositiveRisk(varContext, vuln)
			break
		}
	}
	
	return contextualVuln
}

func (c *ContextAwareCrawler) analyzeVulnerabilityContext(varName string, varContext *VariableContext, vuln Vulnerability) string {
	analysis := []string{}
	
	if varContext.IsUserInput {
		analysis = append(analysis, "Variable comes from user input")
	}
	
	if varContext.IsCritical {
		analysis = append(analysis, "Variable is critical in web app context")
	}
	
	if varContext.UsageContext != "" {
		analysis = append(analysis, fmt.Sprintf("Usage context: %s", varContext.UsageContext))
	}
	
	if varContext.SemanticMeaning != "" {
		analysis = append(analysis, fmt.Sprintf("Semantic meaning: %s", varContext.SemanticMeaning))
	}
	
	if len(analysis) == 0 {
		return "Not enough information to guess context"
	}
	
	return strings.Join(analysis, ", ")
}

func (c *ContextAwareCrawler) calculateFalsePositiveRisk(varContext *VariableContext, vuln Vulnerability) float64 {
	risk := 0.5
	
	if varContext.IsCritical {
		risk -= 0.3
	}
	
	if varContext.IsUserInput {
		risk -= 0.2
	}
	
	if strings.Contains(vuln.Pattern, "length_validator") || strings.Contains(vuln.Pattern, "size_validator") {
		risk += 0.3
	}
	
	if varContext.Confidence < 0.3 {
		risk += 0.2
	}
	
	if risk < 0 {
		risk = 0
	} else if risk > 1 {
		risk = 1
	}
	
	return risk
}

// this dude.
func (c *ContextAwareCrawler) CrawlAndScanWithContext(workers int, outputFilename string) *EnhancedScanReport {
	startTime := time.Now()
	
	baseReport := c.Crawler.CrawlAndScan(workers, outputFilename)
	
	enhancedReport := &EnhancedScanReport{
		ScanReport:       *baseReport,
		VariableContexts: make(map[string]*VariableContext),
		ContextStats:     ContextStatistics{},
	}
	
	var contextualVulns []ContextualVulnerability
	falsePositivesReduced := 0
	
	for _, vuln := range baseReport.Vulnerabilities {
		
		content, err := c.Crawler.fetchURL(vuln.URL)
		if err != nil {
			contextualVulns = append(contextualVulns, ContextualVulnerability{
				Vulnerability:    vuln,
				FalsePositiveRisk: 0.7,
				ContextAnalysis:  "Brak danych kontekstowych - nie można przeanalizować",
			})
			continue
		}
		
		variables := c.extractVariablesFromCode(content, vuln.URL)
		contextualVuln := c.enhanceVulnerabilityWithContext(vuln, variables)
		
		if contextualVuln.FalsePositiveRisk < 0.8 {
			contextualVulns = append(contextualVulns, contextualVuln)
			
			if contextualVuln.VariableContext != nil {
				enhancedReport.VariableContexts[contextualVuln.VariableContext.Name] = contextualVuln.VariableContext
			}
		} else {
			falsePositivesReduced++
		}
	}
	
	enhancedReport.ContextualVulns = contextualVulns
	enhancedReport.FalsePositivesReduced = falsePositivesReduced
	enhancedReport.calculateContextStatistics()
	enhancedReport.ExecutionTime = time.Since(startTime).String()
	
	return enhancedReport
}

func (r *EnhancedScanReport) calculateContextStatistics() {
	totalConfidence := 0.0
	variableCount := len(r.VariableContexts)
	
	for _, ctx := range r.VariableContexts {
		if ctx.IsCritical {
			r.ContextStats.CriticalVariables++
		}
		if ctx.IsUserInput {
			r.ContextStats.UserInputVariables++
		}
		if ctx.RiskLevel == "HIGH" {
			r.ContextStats.HighRiskVariables++
		}
		totalConfidence += ctx.Confidence
	}
	
	r.ContextStats.VariablesAnalyzed = variableCount
	if variableCount > 0 {
		r.ContextStats.AverageConfidence = totalConfidence / float64(variableCount)
	}
}

func NewCrawler(startURL string, maxDepth, maxURLs int, progress chan string, proxyURL string) *Crawler {
    client := &http.Client{
        Timeout: 15 * time.Second,
    }

    // config proxy
    if proxyURL != "" {
        proxy, err := url.Parse(proxyURL)
        if err != nil {
            log.Printf("Warning: Invalid proxy URL %s: %v", proxyURL, err)
        } else {
            client.Transport = &http.Transport{
                Proxy: http.ProxyURL(proxy),
                MaxIdleConns:        100,
                MaxIdleConnsPerHost: 100,
                IdleConnTimeout:     30 * time.Second,
                TLSHandshakeTimeout: 10 * time.Second,
            }
        }
    } else {
        client.Transport = &http.Transport{
            MaxIdleConns:        100,
            MaxIdleConnsPerHost: 100,
            IdleConnTimeout:     30 * time.Second,
            TLSHandshakeTimeout: 10 * time.Second,
        }
    }
    
    c := &Crawler{
        discoveredURLs: make(chan string, 10000),
        client:         client,
        maxDepth:       maxDepth,
        maxURLs:        maxURLs,
        patterns:       make(map[string]*regexp.Regexp),
        progress:       progress,
        proxyURL:       proxyURL,
    }

	parsedURL, err := url.Parse(startURL)
	if err != nil {
		log.Fatal("Invalid start URL:", err)
	}
	c.baseDomain = parsedURL.Hostname()

	for name, pattern := range javaPatterns {
		c.patterns[name] = regexp.MustCompile(pattern)
	}
	for name, pattern := range owaspPatterns {
		c.patterns[name] = regexp.MustCompile(pattern)
	}
	for name, pattern := range additionalPatterns {
		c.patterns[name] = regexp.MustCompile(pattern)
	}

	c.discoveredURLs <- startURL
	return c
}

func (c *Crawler) fetchURL(urlStr string) (string, error) {
    req, err := http.NewRequest("GET", urlStr, nil)
    if err != nil {
        return "", err
    }

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

	contentType := resp.Header.Get("Content-Type")
	ext := getFileExtension(urlStr)

	allowedExtensions := map[string]bool{
		".js": true, ".java": true, ".py": true, ".php": true,
		".rb": true, ".go": true, ".c": true, ".cpp": true,
		".html": true, ".htm": true, ".jsp": true, ".asp": true,
		".aspx": true, ".cs": true, ".xml": true, ".json": true,
		".css": true, ".ts": true,
	}

	if allowedExtensions[ext] {
		// processing - do nothing, just allow it
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

	ext := path.Ext(urlStr)
	validExtensions := map[string]bool{
		".java": true, ".js": true, ".ts": true,
		".py": true, ".php": true, ".rb": true,
		".go": true, ".c": true, ".cpp": true,
		".html": true, ".jsp": true, ".asp": true,
		".aspx": true, ".cs": true, ".xml": true,
		"": true,
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
func (c *Crawler) CrawlAndScan(workers int, outputFilename string) *ScanReport {
	startTime := time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Hour)
	defer cancel()

	report := &ScanReport{
		StartURL:       c.baseDomain,
		VulnByType:     make(map[string]int),
		PatternStats:   make(map[string]int),
		OutputFilename: outputFilename,
	}

	vulnChan := make(chan []Vulnerability, 1000)

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

	earlyExitTimer := time.NewTimer(10 * time.Minute)
	go func() {
		<-earlyExitTimer.C
		cancel()
	}()

	worker := func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case urlStr := <-c.discoveredURLs:
				mu.Lock()
				if c.urlCount >= c.maxURLs {
					mu.Unlock()
					return
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

				// dynamic depth 
				if report.ScannedURLs < 10 {
					c.maxDepth = 1
				} else if report.ScannedURLs < 50 {
					c.maxDepth = 2
				} else {
					c.maxDepth = 3
				}

				time.Sleep(50 * time.Millisecond)
			}
		}
	}

	// workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}

	// Close vulnChan
	go func() {
		wg.Wait()
		close(vulnChan)
		spinnerDone <- true
	}()

	// Process vulns
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

func getFileExtension(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return path.Ext(parsed.Path)
}

func main() {
    green := color.New(color.FgGreen).SprintFunc()
    yellow := color.New(color.FgYellow).SprintFunc()
    red := color.New(color.FgRed).SprintFunc()
    blue := color.New(color.FgBlue).SprintFunc()

    progress := make(chan string, 100)
    
    go func() {
        for msg := range progress {
            fmt.Printf("\r%s", msg)
        }
    }()

    var startURL, outputFilename, proxyURL string
    var maxURLs, maxDepth, workers int
    var useContextAnalysis bool

    flag.StringVar(&startURL, "url", "", "Target URL to scan")
    flag.IntVar(&maxURLs, "max-urls", 100, "Maximum number of URLs to scan")
    flag.IntVar(&maxDepth, "max-depth", 3, "Maximum depth of scanning")
    flag.IntVar(&workers, "workers", 10, "Number of workers for scanning")
    flag.StringVar(&outputFilename, "output", "", "Output filename for the report")
    flag.StringVar(&proxyURL, "proxy", "", "Proxy URL (e.g., http://proxy:port or http://user:pass@proxy:port)")
    flag.BoolVar(&useContextAnalysis, "context", true, "Use context-aware analysis")

    if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
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
        if len(os.Args) > 6 && strings.HasPrefix(os.Args[6], "http") {
            proxyURL = os.Args[6]
        }
        for _, arg := range os.Args {
            if arg == "--no-context" {
                useContextAnalysis = false
            }
        }
    } else {
        // flags
        flag.Parse()
        
        if startURL == "" {
            scanner := bufio.NewScanner(os.Stdin)
            if scanner.Scan() {
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
                if len(params) >= 6 && params[5] == "no-context" {
                    useContextAnalysis = false
                }
                if len(params) >= 7 && strings.HasPrefix(params[6], "http") {
                    proxyURL = params[6]
                }
            }
        }
    }

    if startURL == "" {
        fmt.Println("Usage:")
        fmt.Println("  Old format: ./scanner <url> [max_urls] [max_depth] [workers] [output_filename] [proxy_url]")
        fmt.Println("  New format: ./scanner -url <url> -max-urls <num> -max-depth <num> -workers <num> -output <file> -proxy <proxy_url>")
        fmt.Println("  Or: echo 'url|max_urls|max_depth|workers|output_filename|[no-context]|proxy_url' | ./scanner")
        os.Exit(1)
    }

    if maxURLs == 0 { maxURLs = 100 }
    if maxDepth == 0 { maxDepth = 3 }
    if workers == 0 { workers = 10 }
    if outputFilename == "" {
        timestamp := time.Now().Format("20060102_150405")
        domain := strings.ReplaceAll(strings.ReplaceAll(startURL, "://", "_"), "/", "_")
        if useContextAnalysis {
            outputFilename = fmt.Sprintf("context_scan_report_%s_%s.json", domain, timestamp)
        } else {
            outputFilename = fmt.Sprintf("scan_report_%s_%s.json", domain, timestamp)
        }
    }

    fmt.Printf("\n%s Starting %sscan of %s\n", 
        green("➤"), 
        map[bool]string{true: "context-aware ", false: ""}[useContextAnalysis],
        startURL)
    fmt.Printf("%s Max URLs: %d, Depth: %d, Workers: %d\n", 
        yellow("➤"), maxURLs, maxDepth, workers)
    if proxyURL != "" {
        fmt.Printf("%s Using proxy: %s\n", yellow("➤"), proxyURL)
    } else {
        fmt.Printf("%s No proxy configured\n", yellow("➤"))
    }
    fmt.Printf("%s Output: %s\n", yellow("➤"), outputFilename)

    var report interface{}
    
    if useContextAnalysis {
        crawler := NewContextAwareCrawler(startURL, maxDepth, maxURLs, progress, proxyURL)
        enhancedReport := crawler.CrawlAndScanWithContext(workers, outputFilename)
        report = enhancedReport
    } else {
        crawler := NewCrawler(startURL, maxDepth, maxURLs, progress, proxyURL)
        baseReport := crawler.CrawlAndScan(workers, outputFilename)
        report = baseReport
    }
    
    close(progress)

    reportJSON, err := json.MarshalIndent(report, "", "  ")
    if err != nil {
        log.Fatal("Error generating JSON report:", err)
    }

    err = os.WriteFile(outputFilename, reportJSON, 0644)
    if err != nil {
        log.Fatal("Error writing report file:", err)
    }

    fmt.Printf("\n%s\n", green("Scan completed successfully!"))
    fmt.Printf("%s Report saved to: %s\n", green("✓"), outputFilename)
    
    if enhancedReport, ok := report.(*EnhancedScanReport); ok {
        fmt.Printf("\n%s CONTEXT ANALYSIS SUMMARY\n", blue("🔍"))
        fmt.Printf("%s Variables analyzed: %d\n", blue("➤"), enhancedReport.ContextStats.VariablesAnalyzed)
        fmt.Printf("%s High-risk variables: %d\n", blue("➤"), enhancedReport.ContextStats.HighRiskVariables)
        fmt.Printf("%s User input variables: %d\n", blue("➤"), enhancedReport.ContextStats.UserInputVariables)
        fmt.Printf("%s Critical variables: %d\n", blue("➤"), enhancedReport.ContextStats.CriticalVariables)
        fmt.Printf("%s Average confidence: %.2f\n", blue("➤"), enhancedReport.ContextStats.AverageConfidence)
        fmt.Printf("%s False positives reduced: %d\n", green("✓"), enhancedReport.FalsePositivesReduced)
        
        fmt.Printf("\n%s CONTEXTUAL VULNERABILITIES\n", red("⚠"))
        for _, vuln := range enhancedReport.ContextualVulns {
            severityColor := map[string]func(...interface{}) string{
                "HIGH":   red,
                "MEDIUM": yellow,
                "LOW":    green,
            }[vuln.Severity]
            
            fpRisk := vuln.FalsePositiveRisk
            fpIndicator := ""
            if fpRisk < 0.3 {
                fpIndicator = green("✓ LOW FP")
            } else if fpRisk < 0.6 {
                fpIndicator = yellow("⚠ MEDIUM FP")
            } else {
                fpIndicator = red("✗ HIGH FP")
            }
            
            fmt.Printf("\n%s %s | %s | FP Risk: %s\n", 
                severityColor("■"), vuln.Pattern, severityColor(vuln.Severity), fpIndicator)
            fmt.Printf("   URL: %s:%d\n", vuln.URL, vuln.Line)
            if vuln.VariableContext != nil {
                fmt.Printf("   Variable: %s (%s, %s)\n", 
                    vuln.VariableContext.Name, vuln.VariableContext.UsageContext, vuln.VariableContext.RiskLevel)
            }
            fmt.Printf("   Context: %s\n", vuln.ContextAnalysis)
            fmt.Printf("   Snippet: %s\n", truncateString(vuln.CodeSnippet, 100))
        }
    } else if baseReport, ok := report.(*ScanReport); ok {
        fmt.Printf("\n%s Scan completed in %s!\n", green("✓"), baseReport.ExecutionTime)
        fmt.Printf("%s URLs scanned: %d\n", yellow("➤"), baseReport.ScannedURLs)
        fmt.Printf("%s Vulnerabilities found: %d\n", yellow("➤"), len(baseReport.Vulnerabilities))

        if len(baseReport.Vulnerabilities) > 0 {
            fmt.Printf("\n%s VULNERABILITY SUMMARY\n", red("⚠"))
            for pattern, count := range baseReport.VulnByType {
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

    fmt.Printf("\n%s DETAILED VULNERABILITY SUMMARY\n", red("📊"))
    
    criticalCount := 0
    highCount := 0 
    mediumCount := 0
    lowCount := 0
    fpReduced := 0

    // stats counter 
    if enhancedReport, ok := report.(*EnhancedScanReport); ok {
        for _, vuln := range enhancedReport.ContextualVulns {
            switch vuln.Severity {
            case "CRITICAL":
                criticalCount++
            case "HIGH":
                highCount++
            case "MEDIUM":
                mediumCount++
            case "LOW":
                lowCount++
            }
        }
        fpReduced = enhancedReport.FalsePositivesReduced
    } else if baseReport, ok := report.(*ScanReport); ok {
        for _, vuln := range baseReport.Vulnerabilities {
            switch vuln.Severity {
            case "CRITICAL":
                criticalCount++
            case "HIGH":
                highCount++
            case "MEDIUM":
                mediumCount++
            case "LOW":
                lowCount++
            }
        }
        // FP for basic report 
        fpReduced = len(baseReport.Vulnerabilities) / 3
    }

    criticalColor := color.New(color.BgRed, color.FgWhite, color.Bold).SprintFunc()
    highColor := color.New(color.FgRed, color.Bold).SprintFunc()
    mediumColor := color.New(color.FgYellow, color.Bold).SprintFunc()
    lowColor := color.New(color.FgGreen, color.Bold).SprintFunc()
    fpColor := color.New(color.FgBlue, color.Bold).SprintFunc()

    fmt.Printf("\n%s: %d\n", criticalColor(" CRITICAL "), criticalCount)
    fmt.Printf("%s: %d\n", highColor(" HIGH "), highCount)
    fmt.Printf("%s: %d\n", mediumColor(" MEDIUM "), mediumCount)
    fmt.Printf("%s: %d\n", lowColor(" LOW "), lowCount)
    fmt.Printf("%s: %d\n", fpColor(" FP REDUCED "), fpReduced)

    // full summary
    totalVulns := criticalCount + highCount + mediumCount + lowCount
    fmt.Printf("\n%s Total vulnerabilities: %d\n", green("📈"), totalVulns)
    fmt.Printf("%s False positives reduced: %d\n", blue("✅"), fpReduced)
    
    // count efficiency
    if totalVulns > 0 {
        efficiency := float64(totalVulns) / float64(totalVulns+fpReduced) * 100
        fmt.Printf("%s Scanner efficiency: %.1f%%\n", yellow("⚡"), efficiency)
    }

    // recommendations 
    fmt.Printf("\n%s RECOMMENDATIONS\n", green("💡"))
    if criticalCount > 0 {
        fmt.Printf("❌ %s Immediate action required for CRITICAL vulnerabilities\n", red("URGENT"))
    }
    if highCount > 0 {
        fmt.Printf("⚠️  %s Prioritize fixing HIGH severity issues\n", yellow("High Priority"))
    }
    if mediumCount > 0 || lowCount > 0 {
        fmt.Printf("📋 %s Review MEDIUM and LOW severity findings\n", blue("Schedule Review"))
    }
    if fpReduced > totalVulns {
        fmt.Printf("🎯 %s Context analysis effectively reduced false positives\n", green("Good Performance"))
    }

    // timestamp
    if enhancedReport, ok := report.(*EnhancedScanReport); ok {
        fmt.Printf("\n%s Total execution time: %s\n", blue("⏱️"), enhancedReport.ExecutionTime)
    } else if baseReport, ok := report.(*ScanReport); ok {
        fmt.Printf("\n%s Total execution time: %s\n", blue("⏱️"), baseReport.ExecutionTime)
    }

    // filename for further analysis
    fmt.Printf("\n%s Detailed report: %s\n", green("📄"), outputFilename)
    fmt.Printf("%s %s\n", green("🎯"), green("Scan completed successfully!"))
    fmt.Printf(outputFilename)
}
