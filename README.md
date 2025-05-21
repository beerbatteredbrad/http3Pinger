# HTTP/3 Connection Tester

A PowerShell script to test if a website supports HTTP/3 (QUIC) protocol. This script uses .NET to detect HTTP/3 support by examining the Alt-Svc response header.

## Features

- Detects HTTP/3 support by examining Alt-Svc headers
- Performs DNS resolution and displays IP addresses
- Displays protocol version, response time, and status codes
- Shows detailed certificate information (with `-ShowDetails` parameter)
- Presents all response headers and content samples
- Works with default Windows components (.NET 6+)
- No external dependencies

## Usage

```powershell
# Basic usage
.\TestHttp3.ps1 -Url "https://example.com"

# With detailed information
.\TestHttp3.ps1 -Url "example.com" -ShowDetails
```

The script automatically adds the `https://` prefix if it's missing from the URL.

## Example Output

```
HTTP Protocol Test Results for https://www.cloudflare.com
----------------------------------------
Target: https://www.cloudflare.com (www.cloudflare.com:443)
Test Time: 5/20/2025 10:15:30 AM
Response Time: 327 ms
IP Addresses: 104.16.124.96, 104.16.123.96
Protocol: 2.0
Status: 200 OK
HTTP/3 Support: YES (detected via Alt-Svc header)
Alt-Svc: h3=":443"; ma=86400, h3-29=":443"; ma=86400
Server: cloudflare
Content Type: text/html; charset=utf-8
Content Length: 45384 bytes
HSTS: max-age=31536000

Tip: Use -ShowDetails for more detailed information
```

## Requirements

- PowerShell 5.1 or later
- .NET 6.0 or later
