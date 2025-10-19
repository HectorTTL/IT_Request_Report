# comp_rights_info.ps1

Generates a concise **IT_Request_Report.txt** on the Desktop that captures current user context, elevation status, local admin membership, basic OS details, uptime, network summary, safe permission probes (e.g., write test under `C:\Program Files` with cleanup), ability to read System Event Log, disk info, whoami groups & privileges, plus a brief summary. The report is designed to support helpdesk tickets requesting temporary or permanent admin rights, with evidence gathered **non-elevated** & without making persistent system changes.

## What it does
- Collects user, group, privilege, OS, build, install date, uptime, CPU/RAM basics, active adapters & IPv4s, C: volume info
- Safely probes restricted areas to show limitations (creates a temp file under `C:\Program Files` then deletes it)
- Tries reading System Event Log to demonstrate audit access
- Writes a single UTF-8 (no BOM) output file:  
  `~/Desktop/IT_Request_Report.txt`

## Requirements
- Windows 10/11 with PowerShell 5.1+ (or PowerShell 7.x)
- No external modules, no internet access required

## How to run
**Option A — Explorer**
1. Right-click `comp_rights_info.ps1` & choose **Run with PowerShell**

**Option B — Terminal**
```powershell
# From a non-elevated PowerShell
Set-Location <path-to-repo>
Unblock-File .\comp_rights_info.ps1
powershell -ExecutionPolicy Bypass -File .\comp_rights_info.ps1
