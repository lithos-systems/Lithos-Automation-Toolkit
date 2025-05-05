<#
.SYNOPSIS
    Queries a VTScada REST SQL API endpoint and saves tag names to a text file in C:\VTScada Exports.

.DESCRIPTION
    This script authenticates to a REST SQL API endpoint, runs a query to retrieve tag names
    from a specified VTScada table, and writes the results to a local file.

.COMMAND
    The following line may be pasted directly into PowerShell to directly execute this script:
    iex (iwr "https://raw.githubusercontent.com/lithos-systems/Lithos-Automation-Toolkit/main/VTScada/VTS-Tag-Exporter.ps1")

.PREREQUISITES
    - Ensure that your VTScada application is properly secured.
    - The account used for authentication must have the **Remote Data Access** privilege.
    - While testing, it may be helpful to temporarily grant the **Thin Client** privilege.
    - For access to virtual tables (e.g., tag browsing), the **Remote Tag Value / History Retrieve** privilege may be required.
    - The **Tag Parameter View** privilege may be useful depending on your query.
    
    Refer to the VTScada Reference Guide for additional details on configuring account privileges.
    See: VTScada > Log, Note, and Report > SQL Queries

.NOTES
    You will be prompted to enter the VTScada Application Base URL and Realm. The full API path will be automatically constructed.
#>

# --- USER INPUT ---
$siteUrl = Read-Host "Enter the base URL of your VTScada Application (e.g. https://yourapplication.com)"
$realm = Read-Host "Enter the VTScada realm (e.g. your-realm)"
$username = Read-Host "VTScada Username"
$password = Read-Host "VTScada Password"

# Construct full API endpoint
$baseUrl = "$siteUrl/$realm/REST/SQLQuery"

# --- HEADER SETUP ---
$auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$username`:$password"))
$headers = @{
    "Authorization" = "Basic $auth"
    "Content-Type"  = "application/json"
}

# --- QUERY SETUP ---
$query = "SELECT Name FROM Parms_AllTypes"
$body = @{
    parameters = @{
        query = $query
    }
} | ConvertTo-Json -Depth 10

# --- OUTPUT DIRECTORY SETUP ---
$outputDir = "C:\VTScada Exports"
$outputPath = Join-Path -Path $outputDir -ChildPath "logged_tag_names.txt"

# Ensure output directory exists
if (-not (Test-Path -Path $outputDir)) {
    New-Item -Path $outputDir -ItemType Directory | Out-Null
}

# --- EXECUTION ---
try {
    Write-Host "Sending query to API endpoint: $baseUrl"
    $response = Invoke-RestMethod -Uri $baseUrl -Method POST -Headers $headers -Body $body

    if ($response -and $response.results -and $response.results.values) {
        $tagNames = $response.results.values | ForEach-Object { "$($_[0]):Value" }
        $tagNames | Set-Content -Path $outputPath
        Write-Host "Tag names saved successfully to '$outputPath'."

        # Open the output file
        Start-Process -FilePath $outputPath
    } else {
        Write-Warning "No results were returned from the query."
    }
} catch {
    Write-Error "An error occurred while querying or writing tag names: $_"
}
