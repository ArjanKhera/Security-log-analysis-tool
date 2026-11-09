#Variables with access to log files for use in functions
$PS_LOG = "logs\powershell_log.txt"
$IOC = "logs\ioc.txt"
$AUTH_LOG = "logs\auth.log"
$ACCESS_LOG = "logs\access.log"

#Function for detecting malicious powershell patterns in powershell log. Searches for strings like "EncodedCommand"
#and counts amount of matches in the log file then displays the result.
function detect_powershell_patterns {
    Write-Host "`n===== Detecting Suspicious Patterns in powershell log ====="
    $script:PS_ALERTS = Select-String "EncodedCommand","ExecutionPolicy Bypass","DownloadString","whoami","ipconfig" $PS_LOG
    $script:HTTP_ALERTS = Select-String "Invoke-WebRequest" $PS_LOG  |
            Where-Object {$_.Line -notmatch "https://"}

    If ($script:PS_ALERTS){
        Write-Host "Suspicious Pattern Detected!"
        Write-Host $script:PS_ALERTS.line
        Write-Host "`nTotal alerts:" $script:PS_ALERTS.Count
    } Else{
        Write-Host "No Suspicious Patterns detected!"
    }
    If ($script:HTTP_ALERTS){
        Write-Host "`nInsecure HTTP web requests detected!"
        Write-Host $script:HTTP_ALERTS.line
        Write-Host "`nTotal alerts:" $script:HTTP_ALERTS.Count
    }Else{
        Write-Host "No insecure web requests detected!"
    }
}

#Function for detecting potential brute force login attempts in auth log. The top offending IP addresses are
#recorded and displayed.
function detect_brute_force {
    Write-Host "`n===== Detecting Brute Force Threat in auth.log ====="
    $fail = Select-String "Failed password" $AUTH_LOG
    $script:AUTH_ALERTS = $fail | Where-Object {$fail.Count -ge 5}
    If ($script:AUTH_ALERTS){
        Write-Host "Potential Brute Force Threat Detected!"
        Write-Host "`nTotal failed password attempts:" $fail.Count
        $script:top_IPs = $fail | ForEach-Object {$_.Line} |
        Select-String -Pattern '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' |
        ForEach-Object {$_.Matches.Value} |
        Group-Object | Sort-Object Count -Descending |
        Select-Object -First 5
        Write-Host "Source IP addresses:"
        $script:top_IPs | ForEach-Object {Write-Host " $($_.Name) - $($_.Count) attempts"}
    }Else{
        Write-Host "No Abnormal Login Behaviour Detected!"
    }
}

#Function for detecting suspicious patterns in access log. Patterns are cross referenced from IOC.txt (IP addresses
#and web paths).
function detect_suspicious_access{
    Write-Host "`n===== Detecting Suspicious Access Patterns in access.log ====="
    $ref = Get-Content $IOC | Where-Object {$_ -ne ""}
    $script:ACCESS_ALERTS = Select-String -Pattern $ref -Path $ACCESS_LOG
    If ($script:ACCESS_ALERTS){
        Write-Host "Suspicious Access Patterns Detected!"
        Write-Host ($script:ACCESS_ALERTS|Select-Object -First 5| ForEach-Object {$_.Line})
        Write-Host "`nTotal matches:" $script:ACCESS_ALERTS.Count
    }Else{
        Write-Host "No Suspicious Access Patterns Detected!"
    }
}

#Final function for generating the SOC investigation report and outputting data from each function into the report
#for the analyst to read and scrutinise. Total amount of alert matches are displayed while also informing the user
#if a log file is safe (CLEAR) or contains potential threat indicators (ALERT)
function generate_report {
    If ($script:PS_ALERTS){
        $PS_STATUS = "[ALERT]"
    }Else {$PS_STATUS = "[CLEAR]"}

    If ($script:ACCESS_ALERTS){
        $ACCESS_STATUS = "[ALERT]"
    }Else {$ACCESS_STATUS = "[CLEAR]"}

    If ($script:AUTH_ALERTS){
        $AUTH_STATUS = "[ALERT]"
    }Else {$AUTH_STATUS = "[CLEAR]"}
    $top_IPs_list = $script:top_IPs | ForEach-Object {" $($_.Name) - $($_.Count) attempts" } | Out-String

    $report = @"
==============================================================
SOC Investigation Report
==============================================================

$PS_STATUS PowerShell Log Analysis
Total suspicious patterns/potential threats detected: $($script:PS_ALERTS.Count + $script:HTTP_ALERTS.Count)
Sample: $($script:PS_ALERTS | Select-Object -First 1 | ForEach-Object {$_.Line})

==============================================================

$AUTH_STATUS Auth Log Analysis
Total potential brute force threats: $($script:AUTH_ALERTS.Count)
Sample: $($script:AUTH_ALERTS | Select-Object -First 1 | ForEach-Object {$_.Line})
Top source IP addresses:
$($top_IPs_list)
==============================================================

$ACCESS_STATUS Access Log Analysis
Total suspicious access patterns detected: $($script:ACCESS_ALERTS.Count)
Sample: $($script:ACCESS_ALERTS | Select-Object -First 1 | ForEach-Object {$_.Line})

==============================================================
"@
$report | Out-File investigation_report.txt
Write-Host "Report saved to investigation_report.txt!"
}

detect_powershell_patterns
detect_brute_force
detect_suspicious_access
generate_report