param (
    [switch] $AllowSnapshots, # Whether to fetch snapshot build checksums from the gradle servers (takes longer to run the script)
    [String[]] $AllowChecksums # Array of checksum overrides that count as valid checksums
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

# Find gradle-wrapper.jar files
$wrappers = @()

Get-ChildItem -Path "." -Recurse | ForEach-Object {
    if ($_.Name -Eq "gradle-wrapper.jar") {
        $wrappers += $_.FullName
    }
}

if ($wrappers.Length -Eq 0) {
    Write-Host "Could not find 'gradle-wrapper.jar' file."
    exit
} else {
    Write-Host "Found $($wrappers.Length) gradle wrapper(s) :"
    foreach ($wrapper in $wrappers) {
        $checksum = (Get-FileHash $wrapper -Algorithm SHA256).Hash.ToLower()
        Write-Host "- $($wrapper) ($($checksum))"
    }
}

Write-Host ""

# Get wrapper checksums from gradle api
$checksums = @()
if ($null -Ne $AllowChecksums) {
    $checksums += $AllowChecksums
}

Write-Host "Getting valid checksums from gradle servers... `n"

$gradleVersions = Invoke-RestMethod -Uri "https://services.gradle.org/versions/all"
$finished = 0
foreach ($gradleVersion in $gradleVersions) {
    Write-Progress -Activity "Getting checksums" -PercentComplete ($finished / $gradleVersions.Length * 100)
    $checksumUrl = $gradleVersion.wrapperChecksumUrl
    if ($null -Ne $checksumUrl) {
        if (!($gradleVersion.snapshot) -Or $snapshot) {
            $checksums += Invoke-RestMethod -Uri $checksumUrl
        }
    }
    $finished += 1
}

# Validate wrappers against checksums
Write-Host "Validating wrappers against checksums... `n"

$safe = $true
foreach ($wrapper in $wrappers) {
    $checksum = (Get-FileHash $wrapper -Algorithm SHA256).Hash.ToLower()
    if (-Not $checksums.Contains($checksum)) {
        Write-Host "Found potentially malicious gradle wrapper '$($wrapper)'!"
        $safe = $false
    }
}

if ($safe) {
    Write-Host "Did not find any potentially malicious gradle wrappers."
}
