#!/usr/bin/env python3
"""Decode Microsoft Outlook SafeLinks URLs to extract the original destination. https://github.com/forensicdave/unsafelink"""

import argparse
import json
import re
import subprocess
import sys
import webbrowser
from urllib.parse import urlparse, parse_qs, unquote

__version__ = "1.0.0"

SAFELINKS_DOMAIN_PATTERN = re.compile(r"safelinks\.protection\.outlook\.com")


def decode_safelink(safelink_url, debug=False):
    """Extract the real URL and metadata from an Outlook SafeLinks URL.

    Returns a dict with 'real_url' and optional metadata fields.
    """
    url = safelink_url.strip()

    parsed = urlparse(url)

    if not SAFELINKS_DOMAIN_PATTERN.search(parsed.hostname or ""):
        raise ValueError(
            f"Not a SafeLinks URL (expected safelinks.protection.outlook.com, "
            f"got '{parsed.hostname}')"
        )

    params = parse_qs(parsed.query)

    if "url" not in params:
        raise ValueError("Not a valid SafeLinks URL (no 'url' parameter found)")

    real_url = unquote(params["url"][0])

    result = {"real_url": real_url}
    result["safelinks_host"] = parsed.hostname

    # Parse the 'data' field which contains pipe-delimited metadata
    # Structure: version|flag|recipient|sender-guid|tenant-guid|0|0|timestamp|client|mailflow-b64|...
    if "data" in params:
        data_raw = unquote(params["data"][0])
        data_parts = data_raw.split("|")
        result["data_raw"] = data_raw
        result["data_parts"] = data_parts

        # Map known field positions to labels
        field_labels = {
            0: "version",
            1: "type",
            2: "recipient",
            3: "sender-guid",
            4: "tenant-guid",
            7: "timestamp",
            8: "client",
            9: "mailflow-data",
        }
        result["data_fields"] = {}
        for i, part in enumerate(data_parts):
            if part:
                label = field_labels.get(i, f"field-{i}")
                result["data_fields"][label] = part

    if "sdata" in params:
        # sdata is a digital signature (HMAC) used by Microsoft to verify
        # the SafeLinks URL has not been tampered with
        result["sdata"] = unquote(params["sdata"][0])

    return result


def format_output(result, quiet=False, as_json=False, debug=False):
    """Format the decoded result for display."""
    if as_json:
        return json.dumps(result, indent=2)

    if quiet:
        return result["real_url"]

    lines = []
    lines.append(f"Decoded URL: {result['real_url']}")

    if result.get("data_fields"):
        fields = result["data_fields"]
        if fields.get("recipient"):
            lines.append(f"  Recipient [recipient]: {fields['recipient']}")
        if fields.get("sender-guid"):
            lines.append(f"  Sender GUID [sender-guid]: {fields['sender-guid']}")
        if fields.get("tenant-guid"):
            lines.append(f"  Tenant GUID [tenant-guid]: {fields['tenant-guid']}")
        if fields.get("timestamp"):
            lines.append(f"  Timestamp [timestamp]: {fields['timestamp']}")
        if fields.get("client"):
            lines.append(f"  Client [client]: {fields['client']}")

    if debug:
        if result.get("safelinks_host"):
            lines.append(f"  SafeLinks host: {result['safelinks_host']}")
        if result.get("data_fields"):
            fields = result["data_fields"]
            if fields.get("version"):
                lines.append(f"  Version [version]: {fields['version']}")
            if fields.get("type"):
                lines.append(f"  Type [type]: {fields['type']}")
            if fields.get("mailflow-data"):
                lines.append(f"  Mailflow data [mailflow-data]: {fields['mailflow-data']}")
            # Show any unlabeled fields
            for key, val in fields.items():
                if key.startswith("field-"):
                    lines.append(f"  {key}: {val}")
        if result.get("data_raw"):
            lines.append(f"  Data (raw): {result['data_raw']}")
        if result.get("sdata"):
            lines.append(f"  Signature [sdata]: {result['sdata']}")

    return "\n".join(lines)


def copy_to_clipboard(text):
    """Copy text to system clipboard."""
    if sys.platform == "darwin":
        subprocess.run(["pbcopy"], input=text.encode(), check=True)
    elif sys.platform.startswith("linux"):
        try:
            subprocess.run(["xclip", "-selection", "clipboard"],
                           input=text.encode(), check=True)
        except FileNotFoundError:
            subprocess.run(["xsel", "--clipboard", "--input"],
                           input=text.encode(), check=True)
    elif sys.platform == "win32":
        subprocess.run(["clip"], input=text.encode(), check=True)
    else:
        raise OSError(f"Clipboard not supported on {sys.platform}")


def process_url(url, args):
    """Process a single SafeLinks URL and handle output."""
    try:
        result = decode_safelink(url, debug=args.debug)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return False

    output = format_output(result, quiet=args.quiet, as_json=args.json, debug=args.debug)
    print(output)

    if args.copy:
        try:
            copy_to_clipboard(result["real_url"])
            if not args.quiet:
                print("  (Copied to clipboard)")
        except (OSError, subprocess.CalledProcessError) as e:
            print(f"  Warning: could not copy to clipboard: {e}", file=sys.stderr)

    if args.open:
        webbrowser.open(result["real_url"])

    return True


def main():
    parser = argparse.ArgumentParser(
            description="Decode Microsoft Outlook SafeLinks URLs to reveal the original destination. More dets - https://github.com/forensicdave/unsafelink",
        epilog="Examples:\n"
               "  %(prog)s -u 'https://nam04.safelinks.protection.outlook.com/?url=...'\n"
               "  %(prog)s -u '...' --quiet | xargs open\n"
               "  %(prog)s -f urls.txt --json\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--url", dest="url",
                        help="SafeLinks URL to decode")
    parser.add_argument("-f", "--file", dest="file", metavar="FILE",
                        help="Read SafeLinks URLs from a file (one per line)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Only output the decoded URL (for piping)")
    parser.add_argument("--json", action="store_true",
                        help="Output as structured JSON")
    parser.add_argument("-c", "--copy", action="store_true",
                        help="Copy decoded URL to clipboard")
    parser.add_argument("-o", "--open", action="store_true",
                        help="Open decoded URL in default browser")
    parser.add_argument("--debug", action="store_true",
                        help="Show verbose parsing details")
    parser.add_argument("-V", "--version", action="version",
                        version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    if not args.url and not args.file:
        # Check if there's data on stdin
        if not sys.stdin.isatty():
            args.file = "-"
        else:
            parser.error("one of --url or --file is required")

    success = True

    if args.file:
        source = sys.stdin if args.file == "-" else open(args.file)
        try:
            for line in source:
                line = line.strip()
                if line and not line.startswith("#"):
                    if not process_url(line, args):
                        success = False
                    if not args.quiet and not args.json:
                        print()
        finally:
            if source is not sys.stdin:
                source.close()
    else:
        success = process_url(args.url, args)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
