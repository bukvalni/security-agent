package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"security-agent/internal/config"
	"security-agent/internal/fim"
	"security-agent/internal/logscan"
)

type CombinedReport struct {
	FIM       *fim.FIMResult     `json:"fim_result,omitempty"`
	LogReport *logscan.LogReport `json:"log_report,omitempty"`
	Status    string             `json:"status"`
}

func main() {
	configPath := flag.String("config", "config.json", "Путь к файлу конфигурации")
	initFIM := flag.Bool("init", false, "Создать или обновить эталонный baseline.json")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Printf("Критическая ошибка: %v\n", err)
		os.Exit(1)
	}

	if *initFIM {
		fmt.Println("Инициализация FIM Baseline...")
		err := fim.CreateBaseline(cfg.FIMFiles, cfg.BaselinePath)
		if err != nil {
			fmt.Printf("Ошибка создания эталона: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Эталонный файл %s успешно обновлен!\n", cfg.BaselinePath)
		return
	}

	combinedReport := &CombinedReport{Status: "SECURE"}
	hasAnyAlerts := false

	fimResult, err := fim.CheckIntegrity(cfg.BaselinePath)
	if err != nil {
		fmt.Printf("⚠️ Ошибка модуля FIM: %v\n", err)
	} else {
		combinedReport.FIM = fimResult
		if fimResult.HasAlerts {
			hasAnyAlerts = true
		}
	}

	if cfg.LogFile != "" {
		logReport, err := logscan.AnalyzeLogs(cfg.LogFile, cfg.AttackSignatures)
		if err != nil {
			fmt.Printf("Ошибка модуля LogScan: %v\n", err)
		} else {
			combinedReport.LogReport = logReport
			if logReport.HasAlerts {
				hasAnyAlerts = true
			}
		}
	}

	if hasAnyAlerts {
		combinedReport.Status = "ALERT"
	}

	reportData, err := json.MarshalIndent(combinedReport, "", "  ")
	if err == nil {
		_ = os.WriteFile(cfg.ReportPath, reportData, 0644)
		fmt.Printf("\nИтоговый отчет сохранен в: %s\n", cfg.ReportPath)
	}

	fmt.Println("\n===========================================")
	if hasAnyAlerts {
		fmt.Println("СТАТУС: ОБНАРУЖЕНЫ УГРОЗЫ ИЛИ ИЗМЕНЕНИЯ!")
		os.Exit(1)
	} else {
		fmt.Println("СТАТУС: Безопасность подтверждена. Нарушений нет.")
		os.Exit(0)
	}
}
