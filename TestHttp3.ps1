# This script tests HTTP/3 connectivity using .NET.
# It attempts to detect HTTP/3 support by examining response headers.
#
# Author: beerbatteredbrad
# Version: 1.0
# Created: May 2025
# 
# HTTP/3 is the next generation of the HTTP protocol, built on the QUIC transport protocol.
# It offers improved performance through features like:
# - Reduced connection setup time (0-RTT)
# - Improved congestion control
# - Connection migration
# - Multiplexing without head-of-line blocking
#
# This script helps identify if a server supports HTTP/3 by checking for the Alt-Svc header
# which indicates HTTP/3 (h3) availability.

param (
    [Parameter(Mandatory=$true)]
    [string]$Url,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowDetails
)

# Ensure URL has a protocol prefix
if (-not $Url.StartsWith("http://") -and -not $Url.StartsWith("https://")) {
    $Url = "https://$Url"
    Write-Host "Adding https:// prefix to URL: $Url" -ForegroundColor Yellow
}

# Generate a unique and descriptive class name with timestamp to prevent caching issues
# This ensures each execution of the script uses a fresh class, avoiding type conflicts
$dynamicClassName = "Http3ConnectivityTester_" + (Get-Date).ToString("yyyyMMddHHmmss")

# Inline C# code to test HTTP/3 connectivity
# This code is compiled at runtime to provide HTTP/3 detection capabilities
$CSharpCode = @"
using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public class $dynamicClassName
{
    /**
     * Tests HTTP/3 connectivity for a given URL by examining HTTP headers.
     * Specifically looks for Alt-Svc headers that indicate HTTP/3 support.
     * 
     * @param url     The URL to test for HTTP/3 support
     * @param verbose Whether to collect additional details (certificates, response content samples)
     * @return        TestResult object containing all connectivity information
     */
    public static async Task<TestResult> TestHttp3Connectivity(string url, bool verbose)
    {
        var result = new TestResult();
        result.TargetUrl = url;
        result.TestStartTime = DateTime.Now;
        
        try
        {
            var uri = new Uri(url);
            result.HostName = uri.Host;
            result.IsHttps = uri.Scheme.ToLower() == "https";
            result.Port = uri.Port;
            
            // DNS resolution
            try 
            {
                IPAddress[] addresses = Dns.GetHostAddresses(uri.Host);
                result.IpAddresses = addresses.Select(a => a.ToString()).ToArray();
            }
            catch (Exception dnsEx)
            {
                result.DnsError = string.Format("DNS resolution failed: {0}", dnsEx.Message);
            }
            
            // Use HttpClientHandler for more control
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
            };
            
            // Add verbose certificate validation information if requested
            if (verbose)
            {
                handler.ServerCertificateCustomValidationCallback = 
                    (sender, certificate, chain, sslPolicyErrors) => 
                    {
                        result.CertificateInfo = GetCertificateInfo(certificate, chain, sslPolicyErrors);
                        // Still validate according to policy
                        return sslPolicyErrors == SslPolicyErrors.None;
                    };
            }
            
            using (var client = new HttpClient(handler))
            {
                // Set timeout
                client.Timeout = TimeSpan.FromSeconds(10);
                
                // Add headers to request HTTP/3 if available
                client.DefaultRequestHeaders.Add("Upgrade-Insecure-Requests", "1");
                
                // Add custom headers for better detection
                if (verbose)
                {
                    // Add accept headers for standard web resources
                    client.DefaultRequestHeaders.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
                    client.DefaultRequestHeaders.Add("Accept-Encoding", "gzip, deflate, br");
                    client.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.5");
                    client.DefaultRequestHeaders.Add("User-Agent", "HTTP3-Tester/1.0");
                }
                
                var stopwatch = new Stopwatch();
                stopwatch.Start();
                
                // Send a GET request
                var response = await client.GetAsync(url);
                
                stopwatch.Stop();
                result.ResponseTimeMs = stopwatch.ElapsedMilliseconds;
                
                // Get the protocol version
                result.ProtocolVersion = response.Version.ToString();
                result.StatusCode = (int)response.StatusCode;
                result.ReasonPhrase = response.ReasonPhrase;
                
                // Check if the Alt-Svc header indicates HTTP/3 support
                bool hasAltSvcH3 = false;
                IEnumerable<string> altSvcValues;
                if (response.Headers.TryGetValues("Alt-Svc", out altSvcValues))
                {
                    hasAltSvcH3 = altSvcValues.Any(v => v.Contains("h3"));
                    result.AltSvcHeaderValue = string.Join(", ", altSvcValues);
                }
                
                // Get all response headers
                var headerDict = new Dictionary<string, string>();
                foreach(var header in response.Headers)
                {
                    headerDict[header.Key] = string.Join(", ", header.Value);
                }
                foreach(var header in response.Content.Headers)
                {
                    headerDict[header.Key] = string.Join(", ", header.Value);
                }
                result.HeadersDict = headerDict;
                
                // Format all headers as a string
                result.Headers = string.Join(Environment.NewLine, 
                    headerDict.Select(h => string.Format("{0}: {1}", h.Key, h.Value)));
                
                // Extract specific interesting headers if present
                ExtractInterestingHeaders(result, headerDict);
                  // Get content info
                result.ContentLength = response.Content.Headers.ContentLength != null ? response.Content.Headers.ContentLength.Value : -1;
                result.ContentType = response.Content.Headers.ContentType != null ? response.Content.Headers.ContentType.ToString() : null;
                
                // Set success flags
                result.IsSuccess = response.IsSuccessStatusCode;
                result.IsHttp3Supported = hasAltSvcH3;
                
                // For verbose output, get a sample of the content
                if (verbose)
                {
                    var contentTask = response.Content.ReadAsStringAsync();
                    try
                    {
                        var content = await contentTask;
                        result.ContentSample = content.Length <= 500 ? content : content.Substring(0, 500) + "...";
                    }
                    catch
                    {
                        result.ContentSample = "Could not read content";
                    }
                }
            }
        }
        catch (Exception ex)
        {
            result.IsSuccess = false;
            result.IsHttp3Supported = false;
            result.ErrorMessage = ex.Message;
            result.ErrorType = ex.GetType().Name;
            result.ErrorStackTrace = verbose ? ex.StackTrace : null;
        }
        
        result.TestEndTime = DateTime.Now;
        return result;
    }
      /**
     * Extracts and formats certificate information from the SSL certificate chain
     * 
     * @param certificate    The X509Certificate2 from the SSL handshake
     * @param chain          The certificate chain (if available)
     * @param sslPolicyErrors Any SSL policy errors encountered
     * @return               Formatted string with certificate details
     */
      private static string GetCertificateInfo(X509Certificate2 certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
    {
        if (certificate == null)
            return "No certificate provided";
            
        var info = new System.Text.StringBuilder();
        info.AppendLine("Certificate Information:");
        info.AppendLine(string.Format("  Subject: {0}", certificate.Subject));
        info.AppendLine(string.Format("  Issuer: {0}", certificate.Issuer));
        info.AppendLine(string.Format("  Valid From: {0}", certificate.NotBefore));
        info.AppendLine(string.Format("  Valid To: {0}", certificate.NotAfter));
        info.AppendLine(string.Format("  Serial Number: {0}", certificate.SerialNumber));
        info.AppendLine(string.Format("  Thumbprint: {0}", certificate.Thumbprint));
        info.AppendLine(string.Format("  SSL Policy Errors: {0}", sslPolicyErrors));
        
        if (chain != null)
        {
            info.AppendLine("  Certificate Chain:");
            for (int i = 0; i < chain.ChainElements.Count; i++)
            {
                info.AppendLine(string.Format("    {0}: {1}", i+1, chain.ChainElements[i].Certificate.Subject));
            }
        }
        
        return info.ToString();
    }
    
    /**
     * Extracts specific interesting headers from the response and stores them
     * in the TestResult object for easier access and display
     * 
     * @param result   The TestResult object to populate with header values
     * @param headers  The dictionary of headers from the HTTP response
     */
    private static void ExtractInterestingHeaders(TestResult result, Dictionary<string, string> headers)
    {
        if (headers.ContainsKey("Server"))
            result.ServerHeader = headers["Server"];
            
        if (headers.ContainsKey("X-Powered-By"))
            result.PoweredByHeader = headers["X-Powered-By"];
            
        if (headers.ContainsKey("X-Content-Type-Options"))
            result.ContentTypeOptions = headers["X-Content-Type-Options"];
            
        if (headers.ContainsKey("Strict-Transport-Security"))
            result.HstsHeader = headers["Strict-Transport-Security"];
            
        if (headers.ContainsKey("Cache-Control"))
            result.CacheControl = headers["Cache-Control"];
            
        if (headers.ContainsKey("Alt-Svc"))
            result.AltSvcHeaderValue = headers["Alt-Svc"];
            
        if (headers.ContainsKey("Access-Control-Allow-Origin"))
            result.CorsAllowOrigin = headers["Access-Control-Allow-Origin"];
    }
      public class TestResult
    {
        // Basic information about the target and connection
        public string TargetUrl { get; set; }
        public string HostName { get; set; }
        public bool IsHttps { get; set; }
        public int Port { get; set; }
        public DateTime TestStartTime { get; set; }
        public DateTime TestEndTime { get; set; }
        public long ResponseTimeMs { get; set; }
        
        // Connection results and HTTP protocol information
        public bool IsSuccess { get; set; }
        public bool IsHttp3Supported { get; set; }
        public string ProtocolVersion { get; set; }
        public int StatusCode { get; set; }
        public string ReasonPhrase { get; set; }
        
        // Raw header information
        public string Headers { get; set; }
        public Dictionary<string, string> HeadersDict { get; set; }
        
        // Specific important HTTP headers extracted for easier access
        public string ServerHeader { get; set; }
        public string PoweredByHeader { get; set; }
        public string ContentTypeOptions { get; set; }
        public string HstsHeader { get; set; }
        public string CacheControl { get; set; }
        public string AltSvcHeaderValue { get; set; }
        public string CorsAllowOrigin { get; set; }
        
        // Content metadata and sample
        public long ContentLength { get; set; }
        public string ContentType { get; set; }
        public string ContentSample { get; set; }
        
        // SSL/TLS certificate information
        public string CertificateInfo { get; set; }
        
        // Error handling and diagnostic information
        public string ErrorMessage { get; set; }
        public string ErrorType { get; set; }
        public string ErrorStackTrace { get; set; }
        public string[] IpAddresses { get; set; }
        public string DnsError { get; set; }
    }
}
"@

# Compile the C# code
Add-Type -TypeDefinition $CSharpCode -Language CSharp -ReferencedAssemblies @(
    "System.Net.Http.dll",  # For HTTP client functionality
    "System.dll",           # Core .NET classes
    "System.Core.dll",      # LINQ and other extensions
    "System.Security.dll"   # For certificate handling
)

# Call the TestHttp3Connectivity method
try {
    # Access the dynamic class by its generated name
    $dynamicType = [Type]"$dynamicClassName"
    $Result = $dynamicType::TestHttp3Connectivity($Url, $ShowDetails).GetAwaiter().GetResult()

    Write-Host "HTTP Protocol Test Results for $Url" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    
    if (-not [string]::IsNullOrEmpty($Result.ErrorMessage)) {
        Write-Host "Error: $($Result.ErrorMessage)" -ForegroundColor Red
        if ($ShowDetails -and -not [string]::IsNullOrEmpty($Result.ErrorStackTrace)) {
            Write-Host "Error Type: $($Result.ErrorType)" -ForegroundColor Red
            Write-Host "Stack Trace:" -ForegroundColor Red
            Write-Host $Result.ErrorStackTrace -ForegroundColor Red
        }
    }
    else {
        # Basic info
        Write-Host "Target: $($Result.TargetUrl) ($($Result.HostName):$($Result.Port))" -ForegroundColor Yellow
        Write-Host "Test Time: $($Result.TestStartTime)" -ForegroundColor Yellow
        Write-Host "Response Time: $($Result.ResponseTimeMs) ms" -ForegroundColor Yellow
        
        # IP Address info
        if ($Result.IpAddresses -and $Result.IpAddresses.Count -gt 0) {
            Write-Host "IP Addresses: $($Result.IpAddresses -join ', ')" -ForegroundColor Yellow
        }
        elseif ($Result.DnsError) {
            Write-Host "DNS Resolution: $($Result.DnsError)" -ForegroundColor Red
        }
        
        # Connection info
        Write-Host "Protocol: $($Result.ProtocolVersion)" -ForegroundColor Yellow
        Write-Host "Status: $($Result.StatusCode) $($Result.ReasonPhrase)" -ForegroundColor Yellow
        
        # HTTP/3 Support
        if ($Result.IsHttp3Supported) {
            Write-Host "HTTP/3 Support: YES (detected via Alt-Svc header)" -ForegroundColor Green
            Write-Host "Alt-Svc: $($Result.AltSvcHeaderValue)" -ForegroundColor Green
        }
        else {
            Write-Host "HTTP/3 Support: NO" -ForegroundColor Red
        }
        
        # Server info if available
        if (-not [string]::IsNullOrEmpty($Result.ServerHeader)) {
            Write-Host "Server: $($Result.ServerHeader)" -ForegroundColor Yellow
        }
        
        # Content info
        Write-Host "Content Type: $($Result.ContentType)" -ForegroundColor Yellow
        Write-Host "Content Length: $($Result.ContentLength) bytes" -ForegroundColor Yellow
        
        # Security headers if available
        if (-not [string]::IsNullOrEmpty($Result.HstsHeader)) {
            Write-Host "HSTS: $($Result.HstsHeader)" -ForegroundColor Yellow
        }
        
        # Verbose output
        if ($ShowDetails) {
            Write-Host "`nDetailed Information:" -ForegroundColor Cyan
            Write-Host "----------------------------------------" -ForegroundColor Cyan
            
            # Certificate info
            if (-not [string]::IsNullOrEmpty($Result.CertificateInfo)) {
                Write-Host $Result.CertificateInfo -ForegroundColor Gray
            }
            
            # All headers
            Write-Host "`nAll Response Headers:" -ForegroundColor Cyan
            Write-Host $Result.Headers -ForegroundColor Gray
            
            # Content sample
            if (-not [string]::IsNullOrEmpty($Result.ContentSample)) {
                Write-Host "`nContent Sample:" -ForegroundColor Cyan
                $sampleLength = [Math]::Min(200, $Result.ContentSample.Length)
                Write-Host $Result.ContentSample.Substring(0, $sampleLength) -ForegroundColor Gray
                if ($Result.ContentSample.Length -gt 200) {
                    Write-Host "..." -ForegroundColor Gray
                }
            }
        }
        else {
            Write-Host "`nTip: Use -ShowDetails for more detailed information" -ForegroundColor DarkGray
        }
    }
}
catch {
    Write-Host "Error executing HTTP/3 test: $_" -ForegroundColor Red
}
