package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

type RuleJson struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Regex       string  `json:"regex"`
	SecretGroup int     `json:"secret_group"` // 0 — проверять всё совпадение, 1+ — конкретную группу (...)
	Entropy     float64 `json:"entropy"`      // 0 — проверка энтропии отключена
	Severity    string  `json:"severity"`
}

func getBaseRules() []Rule {

	tgBotToken := Rule{
		ID:          "tg-bot-token",
		Description: "Detected telegram bot token",
		Pattern:     regexp.MustCompile(`\b[0-9]{8,10}:([a-zA-Z0-9_-]{35})\b`),
		SecretGroup: 1,
		Entropy:     3.8,
		Severity:    "WARNING",
	}

	privateKey := Rule{
		ID:          "private-key",
		Description: "Detected private key",
		Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----`),
		Severity:    "WARNING",
	}

	genericApiKey := Rule{
		ID:          "generic-api-key",
		Description: "Detected generic API key",
		Pattern:     regexp.MustCompile("(?i)(?:api[_-]?key|secret|token)\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-]{20,})['\"]"),
		SecretGroup: 1,
		Entropy:     3.8,
		Severity:    "WARNING",
	}

	rules := []Rule{tgBotToken, privateKey, genericApiKey}

	return rules
}

func getPattern(pattern string) (*regexp.Regexp, error) {
	ret, err := regexp.Compile(pattern)

	return ret, err
}

func loadRules(path string) ([]Rule, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rulesJson []RuleJson

	err = json.Unmarshal(file, &rulesJson)
	if err != nil {
		return nil, err
	}

	rules := make([]Rule, 0, len(rulesJson))

	for _, ruleJson := range rulesJson {

		if ruleJson.Regex == "" {
			return nil, fmt.Errorf("%s has bad regex", ruleJson.ID)
		}

		reg, err := getPattern(ruleJson.Regex)
		if err != nil {
			return nil, err
		}

		if ruleJson.SecretGroup < 0 || ruleJson.SecretGroup > reg.NumSubexp() {
			return nil, fmt.Errorf("%s bad regex with secret_group", ruleJson.ID)
		}

		rules = append(rules, Rule{
			ID:          ruleJson.ID,
			Description: ruleJson.Description,
			Pattern:     reg,
			SecretGroup: ruleJson.SecretGroup,
			Entropy:     ruleJson.Entropy,
			Severity:    ruleJson.Severity,
		})
	}

	return rules, nil
}
