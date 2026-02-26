package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/redteamleaders/rtlc2/teamserver/internal/config"
	"github.com/redteamleaders/rtlc2/teamserver/internal/server"
	log "github.com/sirupsen/logrus"
)

var Version = "0.1.0"

func printBanner() {
	fmt.Println("\033[31m")
	fmt.Println("  ____  _____ _     ____ ____  ")
	fmt.Println(" |  _ \\|_   _| |   / ___|___ \\ ")
	fmt.Println(" | |_) | | | | |  | |     __) |")
	fmt.Println(" |  _ <  | | | |__| |___ / __/ ")
	fmt.Println(" |_| \\_\\ |_| |____|\\____|_____|")
	fmt.Println("\033[0m")
	fmt.Printf("  Red Team Leaders - C2 Framework v%s\n", Version)
	fmt.Println("  https://redteamleaders.com")
	fmt.Println()
}

func main() {
	configPath := flag.String("config", "configs/teamserver.yaml", "Path to config file")
	genConfig := flag.Bool("gen-config", false, "Generate default config file and exit")
	version := flag.Bool("version", false, "Show version and exit")

	// Operator management flags
	addOperator := flag.String("add-operator", "", "Add new operator (username)")
	operatorPass := flag.String("password", "", "Password for new operator")
	operatorRole := flag.String("role", "operator", "Role for new operator (admin/operator/viewer)")
	listOperators := flag.Bool("list-operators", false, "List all operators and exit")

	flag.Usage = func() {
		printBanner()
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Server:")
		fmt.Fprintln(os.Stderr, "  -config FILE          Config file path (default: configs/teamserver.yaml)")
		fmt.Fprintln(os.Stderr, "  -gen-config           Generate default config and exit")
		fmt.Fprintln(os.Stderr, "  -version              Show version")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Operator management:")
		fmt.Fprintln(os.Stderr, "  -add-operator NAME    Create a new operator")
		fmt.Fprintln(os.Stderr, "  -password PASS        Password for the new operator")
		fmt.Fprintln(os.Stderr, "  -role ROLE            Role: admin, operator, viewer (default: operator)")
		fmt.Fprintln(os.Stderr, "  -list-operators       List all registered operators")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  rtlc2-teamserver -config configs/teamserver.yaml")
		fmt.Fprintln(os.Stderr, "  rtlc2-teamserver -gen-config")
		fmt.Fprintln(os.Stderr, "  rtlc2-teamserver -add-operator joas -password S3cur3P@ss -role admin")
		fmt.Fprintln(os.Stderr, "  rtlc2-teamserver -list-operators")
		fmt.Fprintln(os.Stderr, "")
	}

	flag.Parse()

	// --- Version ---
	if *version {
		printBanner()
		os.Exit(0)
	}

	// --- Generate config ---
	if *genConfig {
		printBanner()
		cfg := config.DefaultConfig()
		if err := cfg.Save(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to generate config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Default config written to: %s\n", *configPath)
		fmt.Println("[*] Edit the file to add operators, change ports, etc.")
		os.Exit(0)
	}

	// --- Load config ---
	var cfg *config.Config
	var err error

	if _, statErr := os.Stat(*configPath); os.IsNotExist(statErr) {
		fmt.Printf("[!] Config file not found: %s\n", *configPath)
		fmt.Println("[*] Run with -gen-config to create one, or use defaults")
		fmt.Println()
		cfg = config.DefaultConfig()
	} else {
		cfg, err = config.LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to load config '%s': %v\n", *configPath, err)
			fmt.Fprintln(os.Stderr, "[*] Check YAML syntax. Run -gen-config to generate a fresh config.")
			os.Exit(1)
		}
		fmt.Printf("[+] Config loaded: %s\n", *configPath)
	}

	// Validate configuration before proceeding
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}

	// Setup logging to stdout for CLI commands
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		ForceColors:    true,
	})

	// --- Operator management (requires DB) ---
	if *addOperator != "" || *listOperators {
		ts, err := server.New(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to initialize: %v\n", err)
			os.Exit(1)
		}

		if *addOperator != "" {
			password := *operatorPass
			if password == "" {
				fmt.Fprintf(os.Stderr, "[!] Password is required: -password <pass>\n")
				os.Exit(1)
			}
			if err := ts.AddOperator(*addOperator, password, *operatorRole); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to add operator: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("[+] Operator '%s' created (role: %s)\n", *addOperator, *operatorRole)
		}

		if *listOperators {
			if err := ts.ListOperators(); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to list operators: %v\n", err)
				os.Exit(1)
			}
		}

		ts.DB.Close()
		os.Exit(0)
	}

	// --- Start server ---
	printBanner()
	originalAESKey := cfg.Crypto.AESKey
	ts, err := server.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] Failed to initialize team server: %v\n", err)
		os.Exit(1)
	}

	// Auto-persist the generated AES master key so agents survive restarts
	if originalAESKey == "" && cfg.Crypto.AESKey != "" {
		persisted := false
		if data, readErr := os.ReadFile(*configPath); readErr == nil {
			updated := strings.Replace(string(data), `aes_key: ""`, fmt.Sprintf(`aes_key: "%s"`, cfg.Crypto.AESKey), 1)
			if updated != string(data) {
				if writeErr := os.WriteFile(*configPath, []byte(updated), 0600); writeErr == nil {
					persisted = true
				}
			}
		}
		if !persisted {
			// Fallback: save entire config (loses comments but preserves the key)
			if saveErr := cfg.Save(*configPath); saveErr != nil {
				log.Warnf("Could not persist AES key to config: %v", saveErr)
				log.Warnf("Manually add this to your config to persist it:")
				log.Warnf("  aes_key: \"%s\"", cfg.Crypto.AESKey)
			}
		}
		log.Infof("AES master key auto-saved to %s", *configPath)
	}

	if err := ts.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] %v\n", err)
		os.Exit(1)
	}
}
