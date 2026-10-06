package fim

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Baseline map[string]string

type FIMResult struct {
	OKFiles       []string `json:"ok_files"`
	ModifiedFiles []string `json:"modified_files"`
	DeletedFiles  []string `json:"deleted_files"`
	HasAlerts     bool     `json:"has_alerts"`
}

func CalculateHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func CreateBaseline(files []string, baselinePath string) error {
	baseline := make(Baseline)

	for _, file := range files {
		hash, err := CalculateHash(file)
		if err != nil {
			fmt.Printf("[FIM WARNING] Пропущен файл %s: %v\n", file, err)
			continue
		}
		baseline[file] = hash
	}

	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("ошибка сериализации baseline: %w", err)
	}

	if err := os.WriteFile(baselinePath, data, 0644); err != nil {
		return fmt.Errorf("ошибка записи baseline файла: %w", err)
	}

	return nil
}

func CheckIntegrity(baselinePath string) (*FIMResult, error) {
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("эталонный файл %s не найден (запустите с -init)", baselinePath)
	}

	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("ошибка чтения baseline: %w", err)
	}

	result := &FIMResult{
		OKFiles:       make([]string, 0),
		ModifiedFiles: make([]string, 0),
		DeletedFiles:  make([]string, 0),
	}

	fmt.Println("\n=== 🔒 [FIM] Мониторинг целостности файлов ===")

	for filePath, expectedHash := range baseline {
		currentHash, err := CalculateHash(filePath)
		if err != nil {
			fmt.Printf("[DELETED]  Файл удален: %s\n", filePath)
			result.DeletedFiles = append(result.DeletedFiles, filePath)
			result.HasAlerts = true
			continue
		}

		if currentHash != expectedHash {
			fmt.Printf("[MODIFIED] Изменен файл: %s\n", filePath)
			result.ModifiedFiles = append(result.ModifiedFiles, filePath)
			result.HasAlerts = true
		} else {
			fmt.Printf("[OK] %s\n", filePath)
			result.OKFiles = append(result.OKFiles, filePath)
		}
	}

	return result, nil
}
