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
$Wrappers = [System.Collections.Generic.Dictionary[String,String]]::new() # Gradle wrapper paths mapped to their keys
$Properties = [System.Collections.Generic.List[String]]::new() # Gradle properties paths
$PropertyChecksums = [System.Collections.Generic.Dictionary[String,String]]::new() # Gradle properties paths mapped to their 'distributionSha256Sum'
$CheckedVersions = [System.Collections.Generic.HashSet[String]]::new()
$WrapperVersionRegex = [System.Text.RegularExpressions.Regex]::new("distributionUrl=https\\\:\/\/services\.gradle\.org\/distributions\/gradle-([0-9]\.[0-9](?:\.[0-9])?(?:-(?:(?:rc|milestone)-[0-9])|(?:[0-9]{14}\+[0-9]{4}))?)-bin\.zip", "CultureInvariant, Multiline")
$WrapperChecksumRegex = [System.Text.RegularExpressions.Regex]::new("distributionSha256Sum=([0-9a-f]{64})", "CultureInvariant, Multiline")

function Try-Match {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [String] $Hash,
        [String] $Version = "Override"
    )
    process {
        [void]$PropertyChecksums.Remove($Hash)
        if ($Wrappers.Remove($Hash)) {
            Write-Host "Found gradle wrapper version '$($Version)' matching sha256 '$($Hash)'."
        }

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
if ($AllowChecksums.Length -Gt 0) {
    Write-Host "`nValidating wrapper(s) against overrides..."
    ForEach-Object $AllowChecksums {
        Write-Verbose "Processing $($_)"
        Try-Match -Hash $_
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
            $checksum = Invoke-RestMethod -Uri "https://services.gradle.org/distributions/gradle-$($wrapperVersion)-wrapper.jar.sha256" -Method Get
            Try-Match -Hash $checksum -Version $wrapperVersion
            $CheckedVersions += $wrapperVersion
        }
    }
}

# Validate checksums against gradle api
Write-Host "`nValidating wrapper(s) against gradle servers...`n"

(Invoke-RestMethod -Uri "https://services.gradle.org/versions/all" -Method Get -ContentType 'application/json') | Where-Object {
    $_.wrapperChecksumUrl -ne $null -and  # filter distributions without wrapper
    !($CheckedVersions.Contains($_.version))     # filter already checked distributions
} | ForEach-Object {
    Write-Verbose "Processing $($_.version)"
    Try-Match -Hash (Invoke-RestMethod -Uri $_.wrapperChecksumUrl -Method Get) -Version $_.version
}

if ($Wrappers.Count -ne 0) {
    Write-Host "`nFound $($Wrappers.Count) potentially malicious gradle wrapper(s):"
    $Wrappers.GetEnumerator().ForEach({ Write-Host "- $($_.Value) ($($_.Key))" })
}

if ($PropertyChecksums.Count -ne 0) {
    Write-Host "`nFound $($PropertyChecksums.Count) suspicious sha256 checksum(s) in gradle properties:"
    $PropertyChecksums.GetEnumerator().ForEach({ Write-Host "- $($_.Value) ($($_.Key))" })
}

$Stopwatch.Stop()
Write-Host "`nCompleted script execution in $($Stopwatch.ElapsedMilliseconds) ms."