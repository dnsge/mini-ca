package minica

import (
	"bufio"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"time"
)

var scanner = bufio.NewScanner(os.Stdin)

func PromptString(prompt string) string {
	fmt.Print(prompt)
	scanner.Scan()
	return scanner.Text()
}

func PromptDate(prompt string, format string) time.Time {
	for {
		text := PromptString(prompt)
		if text == "" {
			return time.Now()
		}

		t, err := time.Parse(format, text)
		if err != nil {
			fmt.Println("Invalid date")
		} else {
			return t
		}
	}
}

func PromptSubject() pkix.Name {
	return pkix.Name{
		Country:      []string{PromptString("Country Code: ")},
		Organization: []string{PromptString("Organization: ")},
		CommonName:   PromptString("Common Name: "),
	}
}
