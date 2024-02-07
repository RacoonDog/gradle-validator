param (
    [String[]] $AllowChecksums = @() # Array of checksum overrides that count as valid checksums
)

Write-Host "
-------------------------------------------------------------------------------
   ______               ____        _    __      ___     __      __
  / ____/________ _____/ / /__     | |  / /___ _/ (_)___/ /___ _/ /_____  _____
 / / __/ ___/ __ ``/ __  / / _ \    | | / / __ ``/ / / __  / __ ``/ __/ __ \/ ___/
/ /_/ / /  / /_/ / /_/ / /  __/    | |/ / /_/ / / / /_/ / /_/ / /_/ /_/ / /
\____/_/   \__,_/\__,_/_/\___/     |___/\__,_/_/_/\__,_/\__,_/\__/\____/_/

                                                             By crobsby !! :3
-------------------------------------------------------------------------------
"

# Globals
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$Wrappers = New-Object 'System.Collections.Generic.Dictionary[String,String]'
$CheckedVersions = New-Object 'System.Collections.Generic.HashSet[String]'
$WrapperVersionRegex = "(?m)distributionUrl=https\\\:\/\/services\.gradle\.org\/distributions\/gradle-([0-9]\.[0-9](?:\.[0-9])?(?:-(?:(?:rc|milestone)-[0-9])|(?:[0-9]{14}\+[0-9]{4}))?)-bin\.zip"

function Try-Match {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [String] $Hash,
        [String] $Version = "Override"
    )
    process {
        if ($Wrappers.Remove($Hash)) {
            Write-Host "Found gradle wrapper version '$($Version)' matching sha256 '$($Hash)'."
            if ($Wrappers.Count -eq 0) {
                $Stopwatch.Stop()
                Write-Host "`nDid not find any potentially malicious gradle wrappers."
                Write-Host "Completed script execution in $($Stopwatch.ElapsedMilliseconds) ms."
                exit
            }
        }
    }
}

# Search for files
Get-ChildItem -Recurse | Where-Object -Property Name -EQ "gradle-wrapper.jar" | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    $Wrappers[$hash] = $_.FullName
}

if ($Wrappers.Count -Eq 0) { Write-Host "Could not find 'gradle-wrapper.jar' file."; exit }

Write-Host "Found $($Wrappers.Length) gradle wrapper(s) :"
$Wrappers.GetEnumerator().ForEach({ Write-Host "- $($_.Value) ($($_.Key))" })

Write-Host ""

# Validate checksums against overrides
if ($AllowChecksums.Length -Gt 0) {
    Write-Host "Validating wrapper(s) against overrides..."
    ForEach-Object $AllowChecksums | Try-Match -Hash $_
}

# Validate checksums against current distribution via gradle-wrapper.properties
Write-Host "Validating wrapper(s) against current distribution..."

Get-ChildItem -Recurse | Where-Object -Property Name -EQ "gradle-wrapper.properties" | ForEach-Object {Get-Content $_.FullName} | Where-Object {$_ -match $WrapperVersionRegex} | ForEach-Object {
    $version = $Matches[1]
    $checksum = Invoke-RestMethod -Uri "https://services.gradle.org/distributions/gradle-$($version)-wrapper.jar.sha256" -Method Get
    Try-Match -Hash $checksum -Version $version
    $CheckedVersions += $version
}

# Validate checksums against gradle via
Write-Host "Validating wrapper(s) against gradle servers...`n"

(Invoke-RestMethod -Uri "https://services.gradle.org/versions/all" -Method Get -ContentType 'application/json') | Where-Object {
    $_.wrapperChecksumUrl -ne $null -and  # filter distributions without wrapper
    !($CheckedVersions.Contains($_.version))     # filter already checked distributions
} | ForEach-Object {
    Try-Match -Hash (Invoke-RestMethod -Uri $_.wrapperChecksumUrl -Method Get) -Version $_.version
}

Write-Host "`nFound $($Wrappers.Count) potentially malicious gradle wrapper(s):"
$Wrappers.GetEnumerator().ForEach({ Write-Host "- $($_.Value) ($($_.Key))" })
