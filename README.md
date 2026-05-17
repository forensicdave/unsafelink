# unsafelink

A command-line tool to decode Microsoft Outlook SafeLinks URLs and reveal the original destination URL along with embedded metadata.

Available as both a Python script and pre-built Go binaries (no dependencies required).

## What are SafeLinks?

Microsoft Defender for Office 365 wraps URLs in emails with "SafeLinks" — long, encoded URLs that route through Microsoft's scanning proxy before redirecting to the original destination. While this provides click-time protection against malicious links, it makes the actual URL unreadable.

`unsafelink` reverses this encoding, extracting the real URL and any metadata embedded in the SafeLinks wrapper.

## What Safe Links does

When an email arrives, Microsoft scans links in the message. Instead of leaving the original URL intact, it replaces it with a Microsoft-controlled redirect URL.

When the recipient clicks the link:

1. The click goes to Microsoft’s Safe Links service first.
2. Microsoft evaluates the destination URL in real time:
    * malware/phishing reputation
    * detonation/sandbox results
    * tenant policies
    * user targeting signals
3. If the URL is considered safe, the user is redirected to the original destination.
4. If malicious or suspicious, Microsoft shows a warning/interstitial page or blocks access.

This gives Microsoft “time-of-click” protection, which is important because:

* a link might be harmless when the email is delivered
* but later become malicious after the attacker changes the destination content

Safe Links also:

* tracks click telemetry
* supports per-user/policy allow/block behavior
* integrates with Teams, Office apps, and Defender investigations

## Common Safe Links domains

Microsoft uses several Safe Links domains depending on region/cloud:

safelinks.protection.outlook.com
namXX.safelinks.protection.outlook.com
eurXX.safelinks.protection.outlook.com
apcXX.safelinks.protection.outlook.com
emeaXX.safelinks.protection.outlook.com

The subdomain usually indicates:

* geography
* routing cluster
* Microsoft cloud instance

## How redirecting works technically

Simplified flow:

```
User clicks Safe Link
        ↓
Microsoft Safe Links endpoint
        ↓
Policy + reputation checks
        ↓
Allowed?
   ├─ Yes → HTTP redirect (302/307) to original URL
   └─ No  → Warning/block page
```

Microsoft may:

* unwrap nested redirects
* follow shorteners
* inspect final landing pages
* cache verdicts

## Safe Links in Office apps and Teams

Safe Links is not limited to email.

It can protect:

* Outlook email
* Microsoft Teams chats
* Office documents
* SharePoint/OneDrive links
* Office desktop apps

## Security implications

### Benefits

* protects against delayed phishing attacks
* enables real-time blocking
* gives admins telemetry and audit logs
* integrates with Defender/XDR workflows

(In Microsoft Defender XDR / Microsoft 365 Defender Advanced Hunting, Safe Links click activity is primarily exposed through the UrlClickEvents table.)

Great Microsoft reference on this: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table

and some hunting ideas/usage at https://www.michalos.net/2025/03/09/effective-strategies-for-fighting-redirectors-with-urlclickevents-urlchain-devicenetworkevents/

### Downsides

* breaks simple URL matching
* complicates phishing analysis
* can interfere with:
    * link previews
    * signed URLs
    * tracking systems
    * URL parsers
* increases URL length substantially

## Installation

### Option 1: Pre-built binaries (recommended)

Download the binary for your platform from the [Releases](../../releases) page:

| Platform | Binary |
|----------|--------|
| macOS (Apple Silicon) | `unsafelink-darwin-arm64` |
| macOS (Intel) | `unsafelink-darwin-amd64` |
| Linux (x86_64) | `unsafelink-linux-amd64` |
| Linux (ARM64) | `unsafelink-linux-arm64` |
| Windows (x86_64) | `unsafelink-windows-amd64.exe` |

```bash
# macOS/Linux example
chmod +x unsafelink-darwin-arm64
mv unsafelink-darwin-arm64 /usr/local/bin/unsafelink
```

### Option 2: Python script

Requires Python 3.6+ (standard library only, no pip dependencies).

```bash
chmod +x unsafelink.py
```

### Option 3: Build from source (Go)

```bash
cd go/
go build -o unsafelink .
```

## Usage

### Basic decode

```bash
unsafelink -u 'https://nam04.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.com...'
```

Output:

```
Decoded URL: https://example.com/page
  Recipient [recipient]: user@company.com
  Sender GUID [sender-guid]: afa9e80507f34648f03908deb17c4a5a
  Tenant GUID [tenant-guid]: 94986b1d466f4fc0ab4b5c725603deab
  Timestamp [timestamp]: 639143344559541620
  Client [client]: Unknown
```

### Quiet mode (for piping)

```bash
unsafelink -u '...' --quiet
# outputs only: https://example.com/page

# Open directly in browser (macOS)
unsafelink -u '...' -q | xargs open
```

### JSON output

```bash
unsafelink -u '...' --json
```

```json
{
  "real_url": "https://example.com/page",
  "safelinks_host": "nam04.safelinks.protection.outlook.com",
  "data_fields": {
    "version": "05",
    "type": "02",
    "recipient": "user@company.com",
    "sender-guid": "afa9e80507f34648f03908deb17c4a5a",
    "tenant-guid": "94986b1d466f4fc0ab4b5c725603deab",
    "timestamp": "639143344559541620",
    "client": "Unknown",
    "mailflow-data": "TWFpbGZsb3d8eyJFbXB0eU1h..."
  },
  "sdata": "dT9VkOHrUv7FFW2Z5AWg6JWsb5K7Ukyho/4mIaYl/XQ="
}
```

### Batch processing from a file

```bash
unsafelink -f urls.txt
```

The file should contain one SafeLinks URL per line. Lines starting with `#` are ignored.

### Read from stdin

```bash
pbpaste | unsafelink
echo "https://nam04.safelinks..." | unsafelink
```

### Copy decoded URL to clipboard

```bash
unsafelink -u '...' --copy
```

### Open in default browser

```bash
unsafelink -u '...' --open
```

### Debug mode

```bash
unsafelink -u '...' --debug
```

Shows additional detail including the raw data field, mailflow base64 blob, SafeLinks version info, and the integrity signature.

## CLI Options

| Flag | Description |
|------|-------------|
| `-u`, `--url` | SafeLinks URL to decode |
| `-f`, `--file` | Read URLs from a file (one per line) |
| `-q`, `--quiet` | Output only the decoded URL |
| `--json` | Structured JSON output |
| `-c`, `--copy` | Copy decoded URL to clipboard |
| `-o`, `--open` | Open decoded URL in default browser |
| `--debug` | Show verbose parsing details |
| `-V`, `--version` | Print version |

## Decoded Fields

| Field | Description |
|-------|-------------|
| `Decoded URL` | The original destination URL |
| `recipient` | Email address the SafeLink was sent to |
| `sender-guid` | Microsoft internal GUID for the sender |
| `tenant-guid` | Microsoft 365 tenant/organization identifier |
| `timestamp` | .NET ticks timestamp of when the link was wrapped |
| `client` | Mail client type used by the recipient |
| `sdata` (debug) | HMAC signature Microsoft uses to verify URL integrity |
| `mailflow-data` (debug) | Base64-encoded JSON with mail delivery metadata |

## Project Structure

```
.
├── README-unsafelink.md   # This file
├── unsafelink.py          # Python version
├── go/
│   ├── go.mod             # Go module definition
│   └── main.go            # Go source
├── bin/
│   ├── unsafelink-darwin-amd64
│   ├── unsafelink-darwin-arm64
│   ├── unsafelink-linux-amd64
│   ├── unsafelink-linux-arm64
│   └── unsafelink-windows-amd64.exe
├── LICENSE                # MIT License
└── pyproject.toml         # Python packaging config
```

## Use Cases

- **Security analysts** triaging phishing reports who need to see the actual destination URL
- **IT support** helping users who received opaque SafeLinks they don't trust
- **Incident response** extracting metadata (recipient, tenant, timestamps) from SafeLinks in logs
- **Anyone** frustrated by unreadable wrapped URLs in copied email links

## License

MIT
