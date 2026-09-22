# Generic Memory Dump Analysis - Carving and Keyword Extraction
# Analyzes any memory dump (minidump, memdump, full memory capture) for carved strings,
# keywords of interest, and embedded URLs. Prompts for PIDs, paths, and keywords.
# Run from: Guest (no elevation needed)

# ===============================================================================
# INTERACTIVE CONFIGURATION
# ===============================================================================

Write-Host "Memory Dump Analysis Setup" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""

$dumpPathInput = Read-Host "Enter dump file directory (default: C:\dumps)"
$dumpPath = if ([string]::IsNullOrWhiteSpace($dumpPathInput)) { 'C:\dumps' } else { $dumpPathInput }

$pidInput = Read-Host "Enter dump IDs/names (without the file extension), comma-separated (default: dump)"
$dumpIds = if ([string]::IsNullOrWhiteSpace($pidInput)) { @('1', '2', '3') } else { @($pidInput -split ',' | % { $_.Trim() }) }

$minBlockInput = Read-Host "Minimum large block size in chars (default: 1500)"
$minBlockSize = if ([string]::IsNullOrWhiteSpace($minBlockInput)) { 1500 } else { [int]$minBlockInput }

$minFragInput = Read-Host "Minimum fragment size in chars (default: 120)"
$minFragmentSize = if ([string]::IsNullOrWhiteSpace($minFragInput)) { 120 } else { [int]$minFragInput }

$keywordInput = Read-Host "Enter custom keywords comma-separated (leave blank for defaults)"
if ([string]::IsNullOrWhiteSpace($keywordInput)) {
    $keywords = @(
        'http',              # Generic HTTP
        'C:\\',              # Windows paths
        'powershell',        # PowerShell invocation
        'cmd\.exe',          # CMD invocation
        'registry|HKEY',     # Registry access
        'socket|port|conn',  # Network
        'base64|encode',     # Encoding/obfuscation
        'encrypt|decrypt',   # Crypto
        'execute|exec|eval', # Code execution
        'download|upload',   # Exfil
        '\.dll|\.exe|\.ps1', # Binary artifacts
        'thread|process',    # Process manipulation
        'inject|hook',       # Code injection
        '127\.0\.0\.1|\blocalhost\b',  # Loopback
        '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'  # IPv4
    )
} else {
    $keywords = @($keywordInput -split ',' | % { $_.Trim() })
}

# Output directories
$outBase = "$dumpPath\carved"           # Large readable blocks (1500+ chars)
$outFragments = "$dumpPath\fragments"   # Smaller fragments (120+ chars)
$outLog = "$dumpPath\sweep.txt"         # Keyword sweep results

# Character encoding (Latin-1 = no decode errors on arbitrary bytes)
$enc = [Text.Encoding]::GetEncoding(28591)

Write-Host ""
Write-Host "Config loaded: Path=$dumpPath, IDs=$($dumpIds -join ','), BlockSize=$minBlockSize, FragSize=$minFragmentSize" -ForegroundColor Green
Write-Host ""

# ===============================================================================
# STEP 1: CARVE LARGE PRINTABLE BLOCKS
# ===============================================================================
# Extract contiguous readable ASCII/Latin-1 blocks >= $minBlockSize characters.
# Useful for recovering source code, configs, or structured data.

mkdir $outBase -Force | Out-Null

foreach ($id in $dumpIds) {
    $f = "$dumpPath\$id.dmp"
    if (-not (Test-Path $f)) {
        Write-Warning "Dump not found: $f"
        continue
    }

    $size_mb = [math]::Round((Get-Item $f).Length / 1MB, 2)
    Write-Host "Processing: $f ($size_mb MB)" -ForegroundColor Cyan

    $s = $enc.GetString([IO.File]::ReadAllBytes($f))
    $i = 0

    foreach ($m in [regex]::Matches($s, "[\x09\x0A\x0D\x20-\x7E]{$minBlockSize,}")) {
        $i++
        $v = $m.Value
        $n = "$outBase\{0}_{1:D3}_{2}.txt" -f $id, $i, $m.Index
        [IO.File]::WriteAllText($n, $v)
        # Log: filename, length, keyword hits in this block
        $hits = @($keywords | % { if ($v -match $_) { $_ } }).Count
        Write-Host "  [$i] offset=$($m.Index) len=$($v.Length) hits=$hits"
    }

    # Memory cleanup
    $s = $null
    [GC]::Collect()
}

Write-Host "Carved blocks saved to: $outBase" -ForegroundColor Green

# ===============================================================================
# STEP 2: CARVE SMALL FRAGMENTS
# ===============================================================================
# Extract smaller readable fragments ($minFragmentSize - $minBlockSize chars).
# Useful for partial code, config fragments, or task snippets.

mkdir $outFragments -Force | Out-Null

foreach ($id in $dumpIds) {
    $f = "$dumpPath\$id.dmp"
    if (-not (Test-Path $f)) { continue }

    Write-Host "Carving fragments from $id..." -ForegroundColor Cyan
    $s = $enc.GetString([IO.File]::ReadAllBytes($f))
    $i = 0

    foreach ($m in [regex]::Matches($s, "[\x09\x0A\x0D\x20-\x7E]{$minFragmentSize,$($minBlockSize-1)}")) {
        $v = $m.Value
        $n = "$outFragments\{0}_{1:D3}_{2}.txt" -f $id, ++$i, $m.Length
        [IO.File]::WriteAllText($n, $v)
    }

    $s = $null
    [GC]::Collect()
}

Write-Host "Carved fragments saved to: $outFragments" -ForegroundColor Green

# ===============================================================================
# STEP 3: KEYWORD SWEEP - FIND PATTERNS OF INTEREST
# ===============================================================================
# Count keyword occurrences and extract context. Good for identifying capabilities,
# C2 domains, evasion techniques, or known malware signatures.

Write-Host "Running keyword sweep..." -ForegroundColor Cyan

& {
    foreach ($id in $dumpIds) {
        $f = "$dumpPath\$id.dmp"
        if (-not (Test-Path $f)) { continue }

        $s = $enc.GetString([IO.File]::ReadAllBytes($f))

        "==============================================================================="
        "Dump: $id ($f)"
        "==============================================================================="
        ""

        foreach ($k in $keywords) {
            $matches_obj = [regex]::Matches($s, $k, 'IgnoreCase')
            $count = $matches_obj.Count
            if ($count -gt 0) {
                "{0,6} hits  {1}" -f $count, $k
            }
        }

        "-- URLs (http/https) --"
        [regex]::Matches($s, 'https?://[A-Za-z0-9\.\-_/]{1,200}') |
            % Value |
            sort -Unique |
            select -First 100

        "-- IPv4 Addresses --"
        [regex]::Matches($s, '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}') |
            % Value |
            ? { $_ -notmatch '^127\.|^255\.' } |
            sort -Unique |
            select -First 100

        "-- File Paths --"
        [regex]::Matches($s, '[A-Za-z]:\\[A-Za-z0-9\._\-\\]{10,200}') |
            % Value |
            sort -Unique |
            select -First 50

        ""
        $s = $null
        [GC]::Collect()
    }
} *>&1 | Tee-Object $outLog

Write-Host "Keyword sweep results saved to: $outLog" -ForegroundColor Green

# ===============================================================================
# STEP 4: EXTRACT ALL URLS
# ===============================================================================

Write-Host "`nExtracting unique URLs from carved files..." -ForegroundColor Cyan
$allUrls = @()

if (Test-Path $outBase) {
    $allUrls += (Select-String -Path "$outBase\*.txt" `
        -Pattern 'https?://[^\s"''<>]+' -AllMatches -EA 0 |
        % { $_.Matches.Value })
}

if (Test-Path $outFragments) {
    $allUrls += (Select-String -Path "$outFragments\*.txt" `
        -Pattern 'https?://[^\s"''<>]+' -AllMatches -EA 0 |
        % { $_.Matches.Value })
}

if ($allUrls.Count -gt 0) {
    $uniqueUrls = $allUrls | sort -Unique
    Write-Host "Found $($uniqueUrls.Count) unique URLs"
    $uniqueUrls | Out-File "$dumpPath\all_urls.txt"
    Write-Host "URLs saved to: $dumpPath\all_urls.txt"
} else {
    Write-Host "No URLs found"
}

# ===============================================================================
# STEP 5: HASH ALL ARTIFACTS FOR INTEGRITY
# ===============================================================================

Write-Host "`nComputing SHA256 hashes..." -ForegroundColor Cyan
$hashOut = "$dumpPath\artifacts_hash.csv"

Get-ChildItem $outBase, $outFragments -Recurse -File -EA 0 |
    Get-FileHash -Algorithm SHA256 |
    select Hash, Path |
    Export-Csv $hashOut -NoTypeInformation -EA 0

Write-Host "Hashes saved to: $hashOut" -ForegroundColor Green

Write-Host "`nAnalysis complete." -ForegroundColor Cyan
Write-Host "Outputs:"
Write-Host "  Large blocks:  $outBase"
Write-Host "  Fragments:     $outFragments"
Write-Host "  Keyword sweep: $outLog"
Write-Host "  URLs:          $dumpPath\all_urls.txt"
Write-Host "  Hashes:        $hashOut"
