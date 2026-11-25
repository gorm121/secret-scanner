package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
)

type Rule struct {
	ID          string
	Description string
	Pattern     *regexp.Regexp
	Severity    string
}

type Finding struct {
	RuleID   string
	Severity string
	FilePath string
	Line     int
	Match    string
}

func maskSecret(secret string) string {

	secretRunes := []rune(secret)
	length := len(secretRunes)

	resRunes := make([]rune, length)
	for i := 0; i < length; i++ {
		resRunes[i] = '*'
	}
	var visible int
	switch {
	case length <= 8:
		return string(resRunes)
	case length <= 15:
		visible = 1
	case length > 15:
		visible = 2
	}
	for i := 0; i < visible; i++ {
		resRunes[i] = secretRunes[i]
		resRunes[length-1-i] = secretRunes[length-1-i]
	}
	return string(resRunes)
}

func analyzeFile(filePath string, rules []Rule) ([]Finding, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	head := make([]byte, 512)
	n, err := file.Read(head)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	if n == 0 {
		return nil, nil
	}

	if bytes.IndexByte(head[:n], 0) != -1 {
		return nil, nil
	}

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(file)
	const maxCapacity = 10 * 1024 * 1024
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, maxCapacity)

	var numLine int
	var res []Finding

	for scanner.Scan() {
		numLine++
		line := scanner.Text()
		for _, rule := range rules {
			secrets := rule.Pattern.FindAllString(line, -1)

			for _, scrt := range secrets {
				finding := Finding{
					RuleID:   rule.ID,
					Severity: rule.Severity,
					FilePath: filePath,
					Line:     numLine,
					Match:    maskSecret(scrt),
				}
				res = append(res, finding)
			}

		}
	}

	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return res, fmt.Errorf("[{!} analyzeFile] предупреждение: в файле встречена строка длиннее 10MB, сканирование прервано: %w", err)
		}
		return res, fmt.Errorf("[{!} analyzeFile] ошибка чтения файла: %w", err)
	}

	return res, nil
}

func analyzeDirectory(directoryPath string, rules []Rule) ([]Finding, error) {
	skipDirectory := []string{".git", ".idea", "node_modules"}

	var findings []Finding

	err := filepath.WalkDir(directoryPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Printf("[{!} analyzeDirectory] error: %s", err.Error())
			return nil
		}

		if d.IsDir() {
			if slices.Contains(skipDirectory, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		if info.Size() > 157_286_400 {
			log.Printf("[{!} analyzeDirectory] file %s more than 150mb", path)
			return nil
		}

		finding, err := analyzeFile(path, rules)

		if len(finding) != 0 {
			findings = append(findings, finding...)
		}
		if err != nil {
			log.Printf("[{!} analyzeDirectory] %s: %v", path, err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return findings, err

}

func main() {
	var (
		path string
		file string
	)
	flag.StringVar(&path, "path", ".", "directory check")
	flag.StringVar(&file, "file", "", "file check")
	flag.Parse()

	tgBotToken := Rule{
		ID:          "tg-bot-token",
		Description: "Detected telegram bot token",
		Pattern:     regexp.MustCompile(`\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b`),
		Severity:    "WARNING",
	}

	privateKey := Rule{
		ID:          "private-key",
		Description: "Detected private key",
		Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----`),
		Severity:    "WARNING",
	}

	rules := []Rule{tgBotToken, privateKey}
	var findings []Finding
	var err error

	if len(file) != 0 {
		findings, err = analyzeFile(file, rules)
	} else if len(path) != 0 {

		if path == "." {
			path, err = os.Getwd()
			if err != nil {
				panic(err)
			}
			findings, err = analyzeDirectory(path, rules)

		} else {
			findings, err = analyzeDirectory(path, rules)

		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	for _, finding := range findings {
		fmt.Println()
		fmt.Printf("RuleID: %s\n", finding.RuleID)
		fmt.Printf("Severity: %s\n", finding.Severity)
		fmt.Printf("FilePath: %s\n", finding.FilePath)
		fmt.Printf("Line: %d\n", finding.Line)
		fmt.Printf("Match: %s\n", finding.Match)
	}
}
