# DNSFilter Category Check To UDF V7
# Checks DNSFilter category status and reports whether any categories are blocked
# Field: Ninja-Property-Set securityDnsDnsfilterComplianceStatus | Type: Text

#Requirs Certificate be loaded or the web requests will fail depending on which Node a request hits.

<#
-----Version History-----
V1
If a network is not authenticated, pinging myip.dnsfilter.com should return:
"Ping request could not find host myip.dnsfilter.com. Please check the name and try again." or similar.
If a network is authenticated, DNSFilter responds with the IP it sees the request coming from.
"n" flag is number of pings and "w" is the timeout delay in milliseconds.

V2
myip.dnsfilter stopped working for un-authenticated domains. Switched to https://$($category).filterdns.net/status.json

V3
Started checking multiple categories using a foreach loop.

V4
Got all categories working. Added a field for the total number of blocked categories in Datto RMM.

V5
Added check and installation for both DNSFilter and NetAlerts certificates.
Added error handling and a check to confirm the DNSFilter cert is in the root store.
DNSFilter has a secondary certificate used on some servers but not others depending on the deployment and if a site has been authenticated.
Both URLs are included.

V6
Migrated from Datto RMM to NinjaOne. Replaced the Datto registry write with Ninja-Property-Set.
Fixed the category error message (was $(category), now $($category)).
Added a certutil exit code check so failed imports are caught.

V7
Updating SSL/Certificates since I got an alert that vendor has a new Certificate that is used for both standard and MSP and MSP client organizations
KB Link: https://help.dnsfilter.com/hc/en-us/articles/1500008110241-Install-SSL-TLS-certificates-to-display-a-Block-Page-on-HTTPS-based-websites
-Jonathan 11/24/2026
#>

# Function to check and install all DNSFilter Windows related Certificates 
function Install-DNSFilterAndNetAlertsCertificates {
    $certUrls = @{
        "DNSFilter" = "https://app.dnsfilter.com/certs/DNSFilter.cer" #Used when a site isn't authenticated
        "NetAlerts" = "https://app.dnsfilter.com/certs/NetAlerts.cer" #Used for MSP authenticated sites
        "DNSFilter-G1" = "https://app.dnsfilter.com/certs/DNSFilter-G1.cer" #Used for all site types added November 2026
    }
    $success = $true

    foreach ($certName in $certUrls.Keys) {
        $certFile = ".\$certName.cer"

        # Check if the certificate is already in the Root store
        if (Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*$certName*" }) {
            Write-Host -BackgroundColor Green "Verified $certName Cert is already installed"
            continue
        }

        Write-Host -BackgroundColor Red "Couldn't verify $certName Cert is installed. Attempting to add to root store."
        try {
            Invoke-WebRequest -Uri $certUrls[$certName] -OutFile $certFile -UseBasicParsing
            Start-Sleep -Seconds 5

            Write-Host "Importing $certName certificate..."
            certutil -addstore -enterprise -f "Root" $certFile | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "certutil exit code $LASTEXITCODE" }

            Write-Host -BackgroundColor Green "$certName Certificate successfully imported"
        } catch {
            Write-Host -BackgroundColor Red "Failed to install the $certName certificate: $_"
            $success = $false
        }
    }

    return $success
}

# Categories listed on https://debug.dnsfilter.com/
$categories = @(
    'abortion', 'adult', 'alcoholandtobacco', 'blogsandpersonal', 'business', 'contentiousandmisinformation',
    'personals', 'drugs', 'economyandfinance', 'education', 'entertainment', 'foodandrecipes', 'gambling',
    'games', 'government', 'hacking', 'health', 'humor', 'informationtech', 'jobrelated', 'mediasharing',
    'messageboardsandforums', 'newsandmedia', 'illegalcontent', 'realestate', 'religion',
    'searchenginesandportals', 'selfharm', 'socialnetworking', 'shopping', 'sports', 'streamingmedia',
    'terrorismandhate', 'travel', 'vehicles', 'virtualreality', 'weapons', 'chatandmessaging', 'botnet',
    'cryptomining', 'malware', 'newdomains', 'newlyobserveddomains', 'phishing', 'proxyandfilteravoidance',
    'suspiciousanddeceptive', 'translators', 'verynewdomains', 'advertising', 'iwf', 'maliciousdomainprotection',
    'parked', 'trackers', 'uncategorized'
)

# Initialize counters
$BlockedCount = 0
$AllowedCount = 0

# Check and install certificates
if (-not (Install-DNSFilterAndNetAlertsCertificates)) {
    Write-Host -BackgroundColor Red "Certificate installation failed for one or more certificates. Continuing with script execution."
}

# Check category status
foreach ($category in $categories) {
    Write-Host "Checking category: $category"
    try {
        $content = (Invoke-WebRequest -Uri "https://$($category).filterdns.net/status.json" -UseBasicParsing).Content
        Write-Host "Response: $content"

        if ($content -match "true") {
            $BlockedCount++
        } else {
            $AllowedCount++
        }
    } catch {
        Write-Host -BackgroundColor Yellow "Error checking category $($category): $($_.Exception.Message)"
    }
}

# Display results
Write-Host "Allowed Categories: $AllowedCount"
Write-Host "Blocked Categories: $BlockedCount"

# Build the field value
if ($BlockedCount -gt 0) {
    $udf = "True, $BlockedCount of $($categories.Count) Categories Blocked"
} else {
    $udf = "False"
}

Ninja-Property-Set securityDnsDnsfilterComplianceStatus $udf
Write-Host "Security-DNSFilterCategoryStatus = $udf (True = one or more categories blocked; False = none blocked)"