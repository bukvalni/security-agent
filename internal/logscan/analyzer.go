package logscan

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type ThreatEvent struct {
	LineNumber int    `json:"line_number"`
	IP         string `json:"ip"`
	Pattern    string `json:"matched_pattern"`
	RawLine    string `json:"raw_line"`
}

type LogReport struct {
	TotalLines   int            `json:"total_lines"`
	ThreatsCount int            `json:"threats_count"`
	ThreatsByIP  map[string]int `json:"threats_by_ip"`
	Events       []ThreatEvent  `json:"events"`
	HasAlerts    bool           `json:"has_alerts"`
}

func AnalyzeLogs(logPath string, rawSignatures []string) (*LogReport, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка открытия лог-файла %s: %w", logPath, err)
	}
	defer file.Close()

	var patterns []*regexp.Regexp
	for _, sig := range rawSignatures {
		re, err := regexp.Compile("(?i)" + sig)
		if err != nil {
			fmt.Printf("[LOGSCAN WARNING] Некорректная регулярка %q: %v\n", sig, err)
			continue
		}
		patterns = append(patterns, re)
	}

	report := &LogReport{
		ThreatsByIP: make(map[string]int),
		Events:      make([]ThreatEvent, 0),
	}

	scanner := bufio.NewScanner(file)
	lineNumber := 0

	fmt.Println("\n=== 🛡️ [LOGSCAN] Анализ веб-логов безопасности ===")

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		for _, re := range patterns {
			if re.MatchString(line) {
				report.ThreatsCount++
				report.HasAlerts = true

				fields := strings.Fields(line)
				ip := "Unknown"
				if len(fields) > 0 {
					ip = fields[0]
				}

				report.ThreatsByIP[ip]++

				event := ThreatEvent{
					LineNumber: lineNumber,
					IP:         ip,
					Pattern:    re.String(),
					RawLine:    line,
				}
				report.Events = append(report.Events, event)

				fmt.Printf("[ATTACK] Стр.%d | IP: %s | Сигнатура: %s\n", lineNumber, ip, re.String())
				break
			}
		}
	}

	report.TotalLines = lineNumber

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("ошибка сканирования лог-файла: %w", err)
	}

	return report, nil
}
