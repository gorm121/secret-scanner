package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sync"
)

type Rule struct {
	ID          string
	Description string
	Pattern     *regexp.Regexp
	SecretGroup int
	Entropy     float64
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

func analyzeFile(ctx context.Context, filePath string, rules []Rule) ([]Finding, error) {
	var findings []Finding

	if err := ctx.Err(); err != nil {
		return nil, err
	}

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

	for scanner.Scan() {

		if ctx.Err() != nil {
			return findings, ctx.Err()
		}

		numLine++
		line := scanner.Text()
		for _, rule := range rules {
			if rule.Pattern == nil {
				continue
			}
			allMatches := rule.Pattern.FindAllStringSubmatch(line, -1)

			for _, match := range allMatches {

				secret := match[0]

				if rule.SecretGroup > 0 && rule.SecretGroup < len(match) {
					secret = match[rule.SecretGroup]
				}

				if rule.Entropy > 0 && shannonEntropy(secret) < rule.Entropy {
					continue
				}

				finding := Finding{
					RuleID:   rule.ID,
					Severity: rule.Severity,
					FilePath: filePath,
					Line:     numLine,
					Match:    maskSecret(secret),
				}
				findings = append(findings, finding)
			}

		}
	}

	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("[{!} analyzeFile] предупреждение: в файле встречена строка длиннее 10MB, сканирование прервано: %w", err)
		}
		return nil, fmt.Errorf("[{!} analyzeFile] ошибка чтения файла: %w", err)
	}
	return findings, nil
}

func analyzeDirectory(ctx context.Context, directoryPath string, rules []Rule, workers int) ([]Finding, error) {

	var findings []Finding

	skipDirectory := []string{".git", ".idea", "node_modules"}

	jobsChan := make(chan string)
	resultChan := make(chan Finding)

	var wg sync.WaitGroup

	walkErrCh := make(chan error, 1)

	go func() {
		defer close(jobsChan)

		walkErr := filepath.WalkDir(directoryPath, func(path string, d fs.DirEntry, err error) error {

			if ctx.Err() != nil {
				return filepath.SkipAll
			}
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

			select {
			case jobsChan <- path:
				return nil
			case <-ctx.Done():
				return filepath.SkipAll
			}
		})
		walkErrCh <- walkErr
	}()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobsChan {
				fileFindings, err := analyzeFile(ctx, path, rules)
				if err != nil {
					if !errors.Is(err, context.Canceled) {
						log.Printf("[!] %s: %v", path, err)
					}
					continue
				}
				for _, f := range fileFindings {
					select {
					case resultChan <- f:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for res := range resultChan {
		finding := Finding{
			RuleID:   res.RuleID,
			Severity: res.Severity,
			FilePath: res.FilePath,
			Line:     res.Line,
			Match:    res.Match,
		}
		fmt.Println()
		fmt.Printf("RuleID: %s\n", finding.RuleID)
		fmt.Printf("Severity: %s\n", finding.Severity)
		fmt.Printf("FilePath: %s\n", finding.FilePath)
		fmt.Printf("Line: %d\n", finding.Line)
		fmt.Printf("Match: %s\n", finding.Match)

		findings = append(findings, finding)
	}

	if err := <-walkErrCh; err != nil {
		return findings, err
	}

	return findings, ctx.Err()
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	var length float64
	for _, r := range s {
		freq[r]++
		length++
	}

	var entropy float64

	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func main() {
	var (
		path    string
		file    string
		rules   string
		workers int
	)

	var findings []Finding

	flag.StringVar(&path, "path", ".", "directory check")
	flag.StringVar(&file, "file", "", "file check")
	flag.StringVar(&rules, "rules", "", "set rules")
	flag.IntVar(&workers, "workers", runtime.NumCPU(), "set count workers")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var loadedRules []Rule
	var err error

	if len(rules) == 0 {
		loadedRules = getBaseRules()
	} else {
		loadedRules, err = loadRules(rules)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] %d rules have been loaded\n", len(loadedRules))

	if len(file) != 0 {
		findings, err = analyzeFile(ctx, file, loadedRules)
	} else if len(path) != 0 {

		if path == "." {
			path, err = os.Getwd()
			if err != nil {
				panic(err)
			}
			findings, err = analyzeDirectory(ctx, path, loadedRules, workers)

		} else {
			findings, err = analyzeDirectory(ctx, path, loadedRules, workers)
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if ctx.Err() != nil {
		fmt.Println("\n[!] Сканирование прервано пользователем (Ctrl+C).")
	} else {
		fmt.Println("\n[+] Сканирование успешно завершено.")
	}

	fmt.Printf("len of finded = %d", len(findings))
}
