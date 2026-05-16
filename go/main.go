package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

const version = "1.0.0"

var safelinksPattern = regexp.MustCompile(`safelinks\.protection\.outlook\.com`)

type DecodedResult struct {
	RealURL       string            `json:"real_url"`
	SafelinksHost string            `json:"safelinks_host"`
	DataFields    map[string]string `json:"data_fields,omitempty"`
	DataRaw       string            `json:"data_raw,omitempty"`
	SData         string            `json:"sdata,omitempty"`
}

var fieldLabels = map[int]string{
	0: "version",
	1: "type",
	2: "recipient",
	3: "sender-guid",
	4: "tenant-guid",
	7: "timestamp",
	8: "client",
	9: "mailflow-data",
}

func decodeSafelink(safelinkURL string) (*DecodedResult, error) {
	trimmed := strings.TrimSpace(safelinkURL)

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if parsed.Hostname() == "" || !safelinksPattern.MatchString(parsed.Hostname()) {
		return nil, fmt.Errorf("not a SafeLinks URL (expected safelinks.protection.outlook.com, got '%s')", parsed.Hostname())
	}

	params := parsed.Query()
	rawURL := params.Get("url")
	if rawURL == "" {
		return nil, fmt.Errorf("not a valid SafeLinks URL (no 'url' parameter found)")
	}

	result := &DecodedResult{
		RealURL:       rawURL,
		SafelinksHost: parsed.Hostname(),
		DataFields:    make(map[string]string),
	}

	// Parse the 'data' field which contains pipe-delimited metadata
	if data := params.Get("data"); data != "" {
		result.DataRaw = data
		parts := strings.Split(data, "|")
		for i, part := range parts {
			if part == "" {
				continue
			}
			label, ok := fieldLabels[i]
			if !ok {
				label = fmt.Sprintf("field-%d", i)
			}
			result.DataFields[label] = part
		}
	}

	if sdata := params.Get("sdata"); sdata != "" {
		result.SData = sdata
	}

	return result, nil
}

func formatOutput(result *DecodedResult, quiet, asJSON, debug bool) string {
	if asJSON {
		out, _ := json.MarshalIndent(result, "", "  ")
		return string(out)
	}

	if quiet {
		return result.RealURL
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("Decoded URL: %s", result.RealURL))

	if v, ok := result.DataFields["recipient"]; ok {
		lines = append(lines, fmt.Sprintf("  Recipient [recipient]: %s", v))
	}
	if v, ok := result.DataFields["sender-guid"]; ok {
		lines = append(lines, fmt.Sprintf("  Sender GUID [sender-guid]: %s", v))
	}
	if v, ok := result.DataFields["tenant-guid"]; ok {
		lines = append(lines, fmt.Sprintf("  Tenant GUID [tenant-guid]: %s", v))
	}
	if v, ok := result.DataFields["timestamp"]; ok {
		lines = append(lines, fmt.Sprintf("  Timestamp [timestamp]: %s", v))
	}
	if v, ok := result.DataFields["client"]; ok {
		lines = append(lines, fmt.Sprintf("  Client [client]: %s", v))
	}

	if debug {
		lines = append(lines, fmt.Sprintf("  SafeLinks host: %s", result.SafelinksHost))
		if v, ok := result.DataFields["version"]; ok {
			lines = append(lines, fmt.Sprintf("  Version [version]: %s", v))
		}
		if v, ok := result.DataFields["type"]; ok {
			lines = append(lines, fmt.Sprintf("  Type [type]: %s", v))
		}
		if v, ok := result.DataFields["mailflow-data"]; ok {
			lines = append(lines, fmt.Sprintf("  Mailflow data [mailflow-data]: %s", v))
		}
		for key, val := range result.DataFields {
			if strings.HasPrefix(key, "field-") {
				lines = append(lines, fmt.Sprintf("  %s: %s", key, val))
			}
		}
		if result.DataRaw != "" {
			lines = append(lines, fmt.Sprintf("  Data (raw): %s", result.DataRaw))
		}
		if result.SData != "" {
			lines = append(lines, fmt.Sprintf("  Signature [sdata]: %s", result.SData))
		}
	}

	return strings.Join(lines, "\n")
}

func copyToClipboard(text string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
		cmd = exec.Command("xclip", "-selection", "clipboard")
	case "windows":
		cmd = exec.Command("clip")
	default:
		return fmt.Errorf("clipboard not supported on %s", runtime.GOOS)
	}
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("browser open not supported on %s", runtime.GOOS)
	}
	return cmd.Run()
}

func processURL(rawURL string, quiet, asJSON, debug, copyFlag, openFlag bool) bool {
	result, err := decodeSafelink(rawURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return false
	}

	output := formatOutput(result, quiet, asJSON, debug)
	fmt.Println(output)

	if copyFlag {
		if err := copyToClipboard(result.RealURL); err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: could not copy to clipboard: %s\n", err)
		} else if !quiet {
			fmt.Println("  (Copied to clipboard)")
		}
	}

	if openFlag {
		if err := openBrowser(result.RealURL); err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: could not open browser: %s\n", err)
		}
	}

	return true
}

func main() {
	urlFlag := flag.String("u", "", "SafeLinks URL to decode")
	flag.StringVar(urlFlag, "url", "", "SafeLinks URL to decode")

	fileFlag := flag.String("f", "", "Read SafeLinks URLs from a file (one per line)")
	flag.StringVar(fileFlag, "file", "", "Read SafeLinks URLs from a file (one per line)")

	quiet := flag.Bool("q", false, "Only output the decoded URL (for piping)")
	flag.BoolVar(quiet, "quiet", false, "Only output the decoded URL (for piping)")

	asJSON := flag.Bool("json", false, "Output as structured JSON")

	copyFlag := flag.Bool("c", false, "Copy decoded URL to clipboard")
	flag.BoolVar(copyFlag, "copy", false, "Copy decoded URL to clipboard")

	openFlag := flag.Bool("o", false, "Open decoded URL in default browser")
	flag.BoolVar(openFlag, "open", false, "Open decoded URL in default browser")

	debug := flag.Bool("debug", false, "Show verbose parsing details")

	showVersion := flag.Bool("V", false, "Print version")
	flag.BoolVar(showVersion, "version", false, "Print version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "unsafelink v%s - Decode Microsoft Outlook SafeLinks URLs\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: unsafelink [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  unsafelink -u 'https://nam04.safelinks.protection.outlook.com/?url=...'\n")
		fmt.Fprintf(os.Stderr, "  unsafelink -u '...' -q | xargs open\n")
		fmt.Fprintf(os.Stderr, "  unsafelink -f urls.txt --json\n")
		fmt.Fprintf(os.Stderr, "  echo '...' | unsafelink\n")
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("unsafelink v%s\n", version)
		os.Exit(0)
	}

	// Determine input source
	hasStdin := false
	if *urlFlag == "" && *fileFlag == "" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			hasStdin = true
		}
	}

	if *urlFlag == "" && *fileFlag == "" && !hasStdin {
		fmt.Fprintln(os.Stderr, "Error: one of --url or --file is required")
		flag.Usage()
		os.Exit(1)
	}

	success := true

	if *fileFlag != "" || hasStdin {
		var scanner *bufio.Scanner
		if hasStdin || *fileFlag == "-" {
			scanner = bufio.NewScanner(os.Stdin)
		} else {
			f, err := os.Open(*fileFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %s\n", err)
				os.Exit(1)
			}
			defer f.Close()
			scanner = bufio.NewScanner(f)
		}

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !processURL(line, *quiet, *asJSON, *debug, *copyFlag, *openFlag) {
				success = false
			}
			if !*quiet && !*asJSON {
				fmt.Println()
			}
		}
	} else {
		success = processURL(*urlFlag, *quiet, *asJSON, *debug, *copyFlag, *openFlag)
	}

	if !success {
		os.Exit(1)
	}
}
