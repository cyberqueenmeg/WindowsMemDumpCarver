# WindowsMemDumpCarver

A PowerShell-based memory dump carving tool for Windows malware analysis and incident response. Automatically extracts readable content, identifies keywords of interest, and generates forensic artifacts from memory dumps.

## Overview

**WindowsMemDumpCarver** processes Windows memory dumps (minidumps, memdumps, full memory captures) to extract forensically valuable data. The tool carves printable strings, searches for indicators of compromise, and generates structured output for manual analysis.

### Key Features

- **Large Block Carving**: Extract contiguous readable text blocks (configurable size, default 1500+ chars) — useful for recovering source code, configuration files, scripts, and structured data
- **Fragment Carving**: Recover smaller text fragments (120-1500 chars) for partial code, config snippets, or task remnants
- **Keyword Sweep**: Search for malware indicators including:
  - Network artifacts (URLs, IPv4 addresses, C2 domains)
  - File paths and registry access
  - Process/thread manipulation (injection, hooking)
  - Code execution patterns (PowerShell, CMD, execute/eval)
  - Encoding/encryption indicators
  - Binary artifact references (.dll, .exe, .ps1)
- **URL Extraction**: Automatically extract and deduplicate URLs across all carved artifacts
- **Integrity Validation**: Generate SHA256 hashes of all extracted artifacts for chain-of-custody

## Use Cases

- **Malware Analysis**: Recover injected payloads, C2 communication endpoints, and obfuscated code from process memory
- **Incident Response**: Extract attacker artifacts from suspect system memory dumps
- **Forensic Investigation**: Identify lateral movement, exfiltration paths, and execution patterns
- **Memory Hunting**: Search for specific keywords across memory dumps during threat hunts

## Prerequisites

- Windows system with PowerShell (no elevation required)
- Memory dump file(s) in `.dmp` format
- Read access to dump files

## Usage

### Basic Usage

Run the script and follow the interactive prompts:

```powershell
.\WinMemDumpCarver.ps1
```

### Example 1: Analyze a Single Memory Dump

```
Memory Dump Analysis Setup
===================================

Enter dump file directory (default: C:\dumps): C:\incident\dumps
Enter dump IDs/names (without the file extension), comma-separated (default: dump): malware_process
Minimum large block size in chars (default: 1500): 1500
Minimum fragment size in chars (default: 120): 120
Enter custom keywords comma-separated (leave blank for defaults): 
```

This will analyze `C:\incident\dumps\malware_process.dmp` and create:
- `C:\incident\dumps\carved\` — Large readable blocks
- `C:\incident\dumps\fragments\` — Smaller text fragments
- `C:\incident\dumps\sweep.txt` — Keyword search results
- `C:\incident\dumps\all_urls.txt` — Extracted URLs
- `C:\incident\dumps\artifacts_hash.csv` — File integrity hashes

### Example 2: Process Multiple Dumps with Custom Keywords

```
Enter dump file directory (default: C:\dumps): C:\incident\dumps
Enter dump IDs/names (without the file extension), comma-separated (default: dump): suspected_c2, lateral_move, data_exfil
Minimum large block size in chars (default: 1500): 2000
Minimum fragment size in chars (default: 120): 150
Enter custom keywords comma-separated (leave blank for defaults): ransomware.exe, conhost, mimikatz, shadow copy
```

This will analyze three dumps with custom indicators and larger block thresholds.

### Example 3: Extract Only Small Fragments

```
Enter dump file directory (default: C:\dumps): C:\suspect_memory
Enter dump IDs/names (without the file extraction), comma-separated (default: dump): dump
Minimum large block size in chars (default: 1500): 5000
Minimum fragment size in chars (default: 120): 100
Enter custom keywords comma-separated (leave blank for defaults): 
```

By setting a high large-block threshold (5000), most readable content goes to fragments instead.

## Output Format

### Carved Blocks (`carved\`)
Named as: `{dump_id}_{sequence}_{offset}.txt`

Example: `malware_001_4096.txt` contains printable text starting at offset 4096 in the dump. Each file is a single large readable block.

### Fragments (`fragments\`)
Named as: `{dump_id}_{sequence}_{length}.txt`

Example: `malware_042_256.txt` contains a 256-character fragment.

### Keyword Sweep Results (`sweep.txt`)
Structured report showing:
- Keyword hit counts for each dump
- Unique extracted URLs
- Unique IPv4 addresses (excluding loopback and broadcast)
- Unique file paths
- One report per dump file

### URL List (`all_urls.txt`)
Deduplicated URLs extracted from all carved blocks and fragments. One URL per line.

### Artifact Hashes (`artifacts_hash.csv`)
CSV file with columns:
- `Hash` — SHA256 hash of the artifact
- `Path` — Full path to the carved file

Use this to verify artifact integrity during investigation and reporting.

## Configuration Tips

### Adjust Block Sizes
- **Larger blocks (2000+)**: Focuses on complete, coherent data (useful for code/config analysis)
- **Smaller blocks (1000)**: Captures more fragmented content (broader but noisier)
- **Fragment threshold**: Set close to block size to split carved data into two categories

### Custom Keywords
Leave blank to use built-in malware indicators, or supply comma-separated regex patterns:

```
Enter custom keywords: admin$, Domain\, \\\\[a-z]+\share
```

## Technical Details

- **Encoding**: Uses Latin-1 (ISO-8859-1) for decoding — handles arbitrary bytes without errors
- **Regex Matching**: Case-insensitive keyword matching with Unicode flag support
- **Memory Efficiency**: Processes dumps in streaming fashion with garbage collection to handle large files
- **No Elevation Required**: Runs in Guest/User context (assumes read access to dump files)
