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

                                                     Copyright (c) 2024 Crosby
-------------------------------------------------------------------------------
"

# Globals
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$Wrappers = [System.Collections.Generic.Dictionary[String,String]]::new() # Gradle wrapper paths mapped to their keys
$Properties = [System.Collections.Generic.List[String]]::new() # Gradle properties paths
$PropertyChecksums = [System.Collections.Generic.Dictionary[String,String]]::new() # Gradle properties paths mapped to their 'distributionSha256Sum'
$CheckedVersions = [System.Collections.Generic.HashSet[String]]::new()
$WrapperVersionRegex = [System.Text.RegularExpressions.Regex]::new("distributionUrl=https\\\:\/\/services\.gradle\.org\/distributions\/gradle-([0-9]\.[0-9](?:\.[0-9])?(?:-(?:(?:rc|milestone)-[0-9])|(?:[0-9]{14}\+[0-9]{4}))?)-bin\.zip", "CultureInvariant, Multiline")
$WrapperChecksumRegex = [System.Text.RegularExpressions.Regex]::new("distributionSha256Sum=([0-9a-f]{64})", "CultureInvariant, Multiline")

function Match-DistChecksum {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [String] $Hash
    )
    process {
        if ($PropertyChecksums.Remove($Hash)) { Try-Exit }
    }
}

function Match-WrapperChecksum {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [String] $Hash,
        [String] $Version = "Override"
    )
    process {
        if ($Wrappers.Remove($Hash)) {
            Write-Host "Found gradle wrapper version '$($Version)' matching sha256 '$($Hash)'."
            Try-Exit
        }
    }
}

function Try-Exit {
    process {
        if ($Wrappers.Count -eq 0 -and $PropertyChecksums.Count -eq 0) {
            $Stopwatch.Stop()
            Write-Host "`nDid not find any potentially malicious gradle wrappers."
            Write-Host "Completed script execution in $($Stopwatch.ElapsedMilliseconds) ms."
            exit
        }
    }
}

Write-Host "Collecting files..."

# Search for wrappers
Get-ChildItem -Recurse | Where-Object -Property Name -EQ "gradle-wrapper.jar" | ForEach-Object {
    Write-Verbose "Processing $($_.FullName)"
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    $Wrappers[$hash] = $_.FullName
}

if ($Wrappers.Count -eq 0) { Write-Host "`nCould not find any 'gradle-wrapper.jar' files." }
else {
    Write-Host "Found $($Wrappers.Count) gradle wrapper(s) :"
    $Wrappers.GetEnumerator().ForEach({ Write-Host "- $($_.Value) ($($_.Key))" })
}

# Search for properties
Get-ChildItem -Recurse | Where-Object -Property Name -EQ "gradle-wrapper.properties" | ForEach-Object {
    Write-Verbose "Processing $($_.FullName)"
    $Properties += $_.FullName

    $content = Get-Content $_.FullName
    $wrapperChecksumMatch = $WrapperChecksumRegex.Match($content)
    if ($wrapperChecksumMatch.Success) {
        $checksum = $wrapperChecksumMatch.Groups[1].Value
        $PropertyChecksums[$checksum] = $_.FullName
    }
}

if ($Wrappers.Count -eq 0 -and $Properties.Length -eq 0) { exit }

if ($Properties.Length -ne 0) {
    Write-Host "`nFound $($Properties.Length) 'gradle-wrapper.properties' file(s) :"
    $Properties.GetEnumerator().ForEach({ Write-Host "- $($_) " })
}

# Validate checksums against overrides
if ($AllowChecksums.Length -gt 0) {
    Write-Host "`nValidating wrapper(s) against overrides..."
    ForEach-Object $AllowChecksums {
        Write-Verbose "Processing $($_)"
        Match-DistChecksum -Hash $_
        Match-WrapperChecksum -Hash $_
    }
}

# Validate checksums against current distribution via gradle-wrapper.properties
if ($Properties.Length -ne 0) {
    Write-Host "`nValidating wrapper(s) against current distribution..."
    $Properties.GetEnumerator() | ForEach-Object {
        Write-Verbose "Processing $($_)"
        $content = Get-Content -Path $_
        $wrapperVersionMatch = $WrapperVersionRegex.Match($content)
        if ($wrapperVersionMatch.Success) {
            $wrapperVersion = $wrapperVersionMatch.Groups[1].Value
            if ($Wrappers.Count -ne 0) {
                $checksum = Invoke-RestMethod -Uri "https://services.gradle.org/distributions/gradle-$($wrapperVersion)-wrapper.jar.sha256" -Method Get
                Match-WrapperChecksum -Hash $checksum -Version $wrapperVersion
            }
            if ($PropertyChecksums.Count -ne 0) {
                $checksum = Invoke-RestMethod -Uri "https://services.gradle.org/distributions/gradle-$($wrapperVersion)-bin.jar.sha256" -Method Get
                Match-DistChecksum -Hash $checksum
            }
            $CheckedVersions += $wrapperVersion
        }
    }
}

# Validate checksums against gradle api
Write-Host "`nValidating wrapper(s) against gradle servers..."

(Invoke-RestMethod -Uri "https://services.gradle.org/versions/all" -Method Get -ContentType 'application/json') | Where-Object {
    $null -ne $_.wrapperChecksumUrl -and  # filter distributions without wrapper
    !($CheckedVersions.Contains($_.version))     # filter already checked distributions
} | ForEach-Object {
    Write-Verbose "Processing $($_.version)"
    if ($Wrappers.Count -ne 0) {
        Match-WrapperChecksum -Hash (Invoke-RestMethod -Uri $_.wrapperChecksumUrl -Method Get) -Version $_.version
    }
    if ($PropertyChecksums -ne 0 -and $null -ne $_.checksumUrl) {
        Match-DistChecksum -Hash (Invoke-RestMethod -Uri $_.checksumUrl -Method Get)
    }
}

if ($Wrappers.Count -ne 0) {
    Write-Host "`n!!! Found $($Wrappers.Count) potentially malicious gradle wrapper(s):"
    $Wrappers.GetEnumerator().ForEach({ Write-Host "- $($_.Value) ($($_.Key))" })
}

if ($PropertyChecksums.Count -ne 0) {
    Write-Host "`n!!! Found $($PropertyChecksums.Count) suspicious sha256 checksum(s) in gradle properties:"
    $PropertyChecksums.GetEnumerator().ForEach({ Write-Host "- $($_.Key) ($($_.Value))" })
    if ($Wrappers.Count -eq 0) { Write-Host "Since no malicious gradle wrappers were found, this warning can be safely ignored." }
}

$Stopwatch.Stop()
Write-Host "`nCompleted script execution in $($Stopwatch.ElapsedMilliseconds) ms."