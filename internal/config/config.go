package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	FIMFiles         []string `json:"fim_files"`
	BaselinePath     string   `json:"baseline_path"`
	LogFile          string   `json:"log_file"`
	AttackSignatures []string `json:"attack_signatures"`
	ReportPath       string   `json:"report_path"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения конфига %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("ошибка парсинга JSON конфига: %w", err)
	}

	if cfg.BaselinePath == "" {
		cfg.BaselinePath = "baseline.json"
	}
	if cfg.ReportPath == "" {
		cfg.ReportPath = "report.json"
	}

	return &cfg, nil
}
