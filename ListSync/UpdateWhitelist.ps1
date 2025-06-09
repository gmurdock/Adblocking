Add-Type -AssemblyName System.Windows.Forms
Import-Module CredentialManager

# Define working directory path
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$configFile = "$scriptDir\config.json"

# Generates config file with default settings
function Reset-ConfigFile {
	$defaultConfig = @{
		LogDirectory = "$scriptDir\Logs"
		SourceURLs = @(
			"https://raw.githubusercontent.com/cparsell/Blocklists-Whitelists/refs/heads/main/whitelist.txt",
			"https://raw.githubusercontent.com/gmurdock/Adblocking/refs/heads/master/RawWhitelist.txt"
		)  # Default source URLs
		UploadDomain = "https://github.com/gmurdock/Adblocking"
		ProcessedFileURL = "https://raw.githubusercontent.com/gmurdock/Adblocking/refs/heads/git-whitelist/whitelist.txt"  # Destination for processed file
		Email = "user@example.com"
		AbortOnFail = $true
		RetentionType = "Keep last X Lists"
		RetentionValue = 10
		AutoUpdateEnabled = $true
		AutoUpdateInterval = "Monthly"
		MaxGitRetries = 3
	} | ConvertTo-Json

	$defaultConfig | Out-File $configFile
}

# Create default config file when missing
if (!(Test-Path $configFile)) {
	Write-Host "Configuration file missing - creating with default settings."
	Reset-ConfigFile
}

# Load the newly created or existing config
$config = Get-Content $configFile | ConvertFrom-Json
$logDir = $config.LogDirectory
$gitLogFile = "$logDir\git_operations.log"
$whitelistArchiveDir = "$scriptDir\Lists"
$sourceUrls = $config.SourceURLs
$uploadDomain = $config.UploadDomain
$recipientEmail = $config.Email
$abortOnFail = $config.AbortOnFail
$retentionType = $config.RetentionType
$retentionValue = $config.RetentionValue
$smtpServer = "smtp.example.com"
$maxGitRetries = $config.MaxGitRetries

# Ensure archive directory exists
if (!(Test-Path $whitelistArchiveDir)) {
	New-Item -ItemType Directory -Path $whitelistArchiveDir | Out-Null
}

# Retrieve timestamp for script execution
$timestamp = Get-Date -Format "yyyy-MM-dd-THHmmssZ"

# Function to retrieve login token for Git
function Get-GitHubToken {
	$cred = Get-StoredCredential -Target "Git:Adblock"

	if ($cred -and $cred.Password) {
		$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
		$token = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
		return $token.Trim()
	} else {
		Write-Host "ERROR: GitHub token not found in Windows Credential Manager."
		exit 1
    }
}
# Append token and set Git authentication
$githubToken = Get-GitHubToken
git remote set-url origin https://$githubToken@github.com/gmurdock/Adblocking.git

# Execution Context Detection
function Test-ExecutionContext {
	$sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
	return ($sid -eq "S-1-5-18")  # SYSTEM-context SID
}
$runningAsSystem = Test-ExecutionContext
$autoRun = $runningAsSystem

# Logging function with timestamps
function Write-TimestampedLog {
	param([string]$message)
	$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
	"$timestamp - $message" | Out-File -Append -FilePath "$logDir\whitelist_processing.log"
}

Write-TimestampedLog "Script Execution Started."

# Scheduled Task Management for Auto-Update
function New-ScheduledTask {
	param([string]$taskName, [string]$interval)

	$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptDir\whitelist_updater.ps1`" -WindowStyle Hidden"

	# Define trigger based on user preference
	$trigger = switch ($interval) {
		"Daily"		{ 	New-ScheduledTaskTrigger 	-Daily 									-At "09:00AM" }
		"Weekly"	{ 	New-ScheduledTaskTrigger 	-Weekly 	-DaysOfWeek 	Sunday 		-At "09:00AM" }
		"Monthly"	{ 	New-ScheduledTaskTrigger 	-Monthly 	-DaysOfMonth 	1 			-At "09:00AM" }
	}

	Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User "SYSTEM" -Force
}

function Remove-ScheduledTask {
	param([string]$taskName)

	if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
		Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
	}
}

if ($config.AutoUpdateEnabled) {
	Create-ScheduledTask -taskName "AdblockUpdate -Whitelist" -interval $config.AutoUpdateInterval
} else {
	Remove-ScheduledTask -taskName "AdblockUpdate -Whitelist"
}

# Self-Update Mechanism with Error Handling
function Update-List {
	$latestVersionUrl = "https://example.com/latest_version.txt"
	$scriptDownloadUrl = "https://example.com/whitelist_updater.ps1"
	$localVersionFile = "$scriptDir\script_version.txt"

	try {
		$latestVersion = Invoke-WebRequest -Uri $latestVersionUrl -ErrorAction Stop | Select-Object -ExpandProperty Content
	} catch {
		Write-TimestampedLog "ERROR: Failed to fetch latest version from server."
		return
	}

	if ((Test-Path $localVersionFile) -and (Get-Content $localVersionFile) -eq $latestVersion) {
		Write-TimestampedLog "No script update required."
		return
	}

	Write-TimestampedLog "Updating script to latest version..."
	Invoke-WebRequest -Uri $scriptDownloadUrl -OutFile "$scriptDir\whitelist_updater.ps1"

	$latestVersion | Out-File $localVersionFile

	Show-ToastNotification -Title "Whitelist Updater Updated" -Message "The latest version has been installed."
}

# Validate Source URLs Before Processing
$failedSources = @()
foreach ($url in $sourceUrls) {
	try {
		$response = Invoke-WebRequest -Uri $url -Method Head -ErrorAction Stop
		if ($response.StatusCode -ne 200) {
			$failedSources += $url
		}
	} catch {
		$failedSources += $url
	}
}

if ($abortOnFail -and $failedSources.Count -gt 0) {
	Write-TimestampedLog "ERROR: The following sources are unreachable: $($failedSources -join ', ')"
	Show-ToastNotification -Title "Update Failed" -Message "Whitelist update aborted due to unreachable sources."
	Exit 1
}

Write-TimestampedLog "Downloading whitelist data..."
$mergedData = @()
foreach ($url in $sourceUrls) {
    try {
        $data = Invoke-WebRequest -Uri $url -UseBasicParsing | Select-Object -ExpandProperty Content
        $mergedData += $data -split "`n"
    } catch {
        Write-TimestampedLog "WARNING: Failed to retrieve data from $url"
    }
}

Write-TimestampedLog "Processing entries..."
$processedDomains = $mergedData | ForEach-Object {
    $_ -replace "\#.*", "" -replace "\s+$", "" -replace "^\*+", "" | Where-Object {$_ -match "^[a-zA-Z0-9.-]+$"}
} | Sort-Object | Get-Unique

$outputFile = "$whitelistArchiveDir\Whitelist-$timestamp.txt"
$processedDomains | Out-File $outputFile -Encoding utf8

Write-TimestampedLog "Archived processed list: $outputFile"
Write-TimestampedLog "Uploading processed whitelist..."
git add $outputFile
git commit -m "Updated and processed domain list"
git push origin $config.UploadBranch  # Pushes to the correct branch

# Git Operations with Logging & Retry Logic
$retryCount = 0
$gitSuccess = $false

do {
	Write-TimestampedLog "Attempt $($retryCount+1): Pushing processed whitelist..."
	$gitOutput = & git push origin main 2>&1
	"$timestamp - Attempt ${retryCount}: $gitOutput`r`n" | Out-File -Append -FilePath $gitLogFile

	if ($gitOutput -match "fatal|error") {
		Write-TimestampedLog "Git push failed, retrying..."
		Start-Sleep -Seconds 5
	} else {
		$gitSuccess = $true
	}

	$retryCount++
} until ($gitSuccess -or $retryCount -ge $maxGitRetries)

if (-not $gitSuccess) {
	Write-TimestampedLog "ERROR: Git operations failed after $maxGitRetries attempts."
	Show-ToastNotification -Title "Git Upload Failed" -Message "See log file for details: $gitLogFile"
	Exit 1
}

Write-TimestampedLog "Update Complete."