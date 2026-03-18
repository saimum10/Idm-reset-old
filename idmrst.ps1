# ==============================================================
#  IDM Trial Reset - Pure PowerShell (Online Version)
#  Based on: github.com/J2TEAM/idm-trial-reset
#            github.com/WindowsAddict/IDM-Activation-Script
#  Usage: irm https://raw.githubusercontent.com/saimum10/Idm-reset-old/main/idmrst.ps1 | iex
#  Features: Trial Reset + Freeze Trial + Register Simulation
# ==============================================================

# ── 1. Self-Elevation ──────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -Command `"irm 'https://raw.githubusercontent.com/saimum10/Idm-reset-old/main/idmrst.ps1' | iex`"" -Verb RunAs
    exit
}

# ── 2. Privilege Enable ────────────────────────────────────────
$privCode = @"
using System;
using System.Runtime.InteropServices;
public class WinPrivilege {
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr h, uint a, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref TP n, uint l, IntPtr p, IntPtr r);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern bool LookupPrivilegeValue(string s, string n, out LUID l);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] struct LA   { public LUID Luid; public uint Attr; }
    [StructLayout(LayoutKind.Sequential)] struct TP   { public uint Count; public LA Priv; }
    public static void Enable(string name) {
        IntPtr tok; if (!OpenProcessToken(GetCurrentProcess(), 0x28, out tok)) return;
        LUID luid; LookupPrivilegeValue(null, name, out luid);
        TP tp; tp.Count=1; tp.Priv.Luid=luid; tp.Priv.Attr=2;
        AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
"@
Add-Type -TypeDefinition $privCode -Language CSharp -ErrorAction SilentlyContinue
[WinPrivilege]::Enable("SeRestorePrivilege")
[WinPrivilege]::Enable("SeTakeOwnershipPrivilege")

# ── 3. Architecture Detection ──────────────────────────────────
$arch = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment").PROCESSOR_ARCHITECTURE
$is64 = ($arch -ne "x86")

if ($is64) {
    $script:CLSID    = "HKCU:\Software\Classes\Wow6432Node\CLSID"
    $script:CLSIDr   = "HKCU\Software\Classes\Wow6432Node\CLSID"
    $script:HKLM_IDM = "HKLM\SOFTWARE\Wow6432Node\Internet Download Manager"
    $script:IDMan    = "${env:ProgramFiles(x86)}\Internet Download Manager\IDMan.exe"
} else {
    $script:CLSID    = "HKCU:\Software\Classes\CLSID"
    $script:CLSIDr   = "HKCU\Software\Classes\CLSID"
    $script:HKLM_IDM = "HKLM\Software\Internet Download Manager"
    $script:IDMan    = "$env:ProgramFiles\Internet Download Manager\IDMan.exe"
}

$regIDMan = (Get-ItemProperty "HKCU:\Software\DownloadManager" -Name "ExePath" -ErrorAction SilentlyContinue).ExePath
if ($regIDMan -and (Test-Path $regIDMan)) { $script:IDMan = $regIDMan }

# ── 4. IDM GUIDs ──────────────────────────────────────────────
$script:allkeys = @(
    '{6DDF00DB-1234-46EC-8356-27E7B2051192}',
    '{7B8E9164-324D-4A2E-A46D-0165FB2000EC}',
    '{D5B91409-A8CA-4973-9A0B-59F713D25671}',
    '{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}',
    '{07999AC3-058B-40BF-984F-69EB1E554CA7}'
)
$script:dynamicKey = $null

# ── 5. Helper: 4 registry paths per GUID ──────────────────────
function Get-GuidPaths($guid) {
    return @(
        "HKCU\Software\Classes\CLSID\$guid",
        "HKCU\Software\Classes\Wow6432Node\CLSID\$guid",
        "HKLM\Software\Classes\CLSID\$guid",
        "HKLM\Software\Classes\Wow6432Node\CLSID\$guid"
    )
}

# ── 6. Helper: Open registry key ──────────────────────────────
function Open-RegKey($path, [System.Security.AccessControl.RegistryRights]$rights) {
    if ($path -match "^HKCU\\") { $hive = [Microsoft.Win32.Registry]::CurrentUser;  $sub = $path -replace "^HKCU\\","" }
    else                         { $hive = [Microsoft.Win32.Registry]::LocalMachine; $sub = $path -replace "^HKLM\\","" }
    try { return $hive.OpenSubKey($sub, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $rights) }
    catch { return $null }
}

# ── 7. Unlock locked keys before editing ──────────────────────
function Unlock-RegKeys {
    $me      = [System.Security.Principal.NTAccount]([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
    $admins  = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $everyone= New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
    $fullRule= New-Object System.Security.AccessControl.RegistryAccessRule(
        $admins,
        [System.Security.AccessControl.RegistryRights]::FullControl,
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)

    foreach ($g in $script:allkeys) {
        foreach ($p in (Get-GuidPaths $g)) {
            # Take ownership
            $key = Open-RegKey $p ([System.Security.AccessControl.RegistryRights]::TakeOwnership)
            if ($key) {
                try {
                    $acl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
                    $acl.SetOwner($me); $key.SetAccessControl($acl)
                } catch {} finally { $key.Close() }
            }
            # Remove deny rules + restore permissions
            $key = Open-RegKey $p ([System.Security.AccessControl.RegistryRights]::ChangePermissions)
            if ($key) {
                try {
                    $acl = $key.GetAccessControl()
                    $rules = $acl.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
                    foreach ($r in $rules) { $acl.RemoveAccessRule($r) | Out-Null }
                    $acl.SetAccessRuleProtection($false, $true)
                    $acl.AddAccessRule($fullRule)
                    $key.SetAccessControl($acl)
                } catch {} finally { $key.Close() }
            }
        }
    }
}

# ── 8. J2TEAM RegSearch: dynamic GUID ─────────────────────────
function Find-DynamicKey {
    $tmp = "$env:TEMP\reg_query.tmp"
    cmd /c "reg query hkcr\clsid /s > `"$tmp`"" 2>$null
    $found = $null
    if (Test-Path $tmp) {
        $lines = Get-Content $tmp -Encoding Default
        $hitIdx = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match 'cDTvBFquXk0') { $hitIdx = $i; break }
        }
        if ($hitIdx -ge 0) {
            for ($j = $hitIdx; $j -ge 0; $j--) {
                if ($lines[$j] -match '\{[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}') {
                    $found = $Matches[0]; break
                }
            }
        }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }
    return $found
}

# ── 9. IAS RegScan ────────────────────────────────────────────
function Find-IDMKeys {
    $finalValues = @()
    $subKeysToExclude = @("LocalServer32","InProcServer32","InProcHandler32")
    Write-Host "  Scanning IDM CLSID keys..." -ForegroundColor Gray
    $lockedKeys = @()
    $subKeys = Get-ChildItem -Path $script:CLSID -ErrorAction SilentlyContinue -ErrorVariable lockedKeys |
               Where-Object { $_.PSChildName -match '^\{[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}$' }
    foreach ($lk in $lockedKeys) {
        $leaf = Split-Path -Path $lk.TargetObject -Leaf
        $finalValues += $leaf
    }
    if ($subKeys) {
        $filtered = $subKeys | Where-Object { !($_.GetSubKeyNames() | Where-Object { $subKeysToExclude -contains $_ }) }
        foreach ($key in $filtered) {
            $fullPath  = $key.PSPath
            $keyValues = Get-ItemProperty -Path $fullPath -ErrorAction SilentlyContinue
            $defVal    = $keyValues.PSObject.Properties | Where-Object { $_.Name -eq '(default)' } | Select-Object -ExpandProperty Value
            if (($defVal -match "^\d+$") -and ($key.SubKeyCount -eq 0)) { $finalValues += $key.PSChildName; continue }
            if (($defVal -match "\+|=") -and ($key.SubKeyCount -eq 0))  { $finalValues += $key.PSChildName; continue }
            $verVal = Get-ItemProperty -Path "$fullPath\Version" -ErrorAction SilentlyContinue |
                      Select-Object -ExpandProperty '(default)' -ErrorAction SilentlyContinue
            if (($verVal -match "^\d+$") -and ($key.SubKeyCount -eq 1)) { $finalValues += $key.PSChildName; continue }
            $keyValues.PSObject.Properties | ForEach-Object {
                if ($_.Name -match "MData|Model|scansk|Therad") { $finalValues += $key.PSChildName }
            }
            if (($key.ValueCount -eq 0) -and ($key.SubKeyCount -eq 0)) { $finalValues += $key.PSChildName }
        }
    }
    return @($finalValues | Select-Object -Unique)
}

# ── 10. IAS Delete Trial Values ────────────────────────────────
function Remove-TrialValues {
    $dmPath = "HKCU:\Software\DownloadManager"
    @("FName","LName","Email","Serial","scansk","tvfrdt","radxcnt","LstCheck","ptrk_scdt","LastCheckQU") | ForEach-Object {
        Remove-ItemProperty -Path $dmPath -Name $_ -ErrorAction SilentlyContinue
    }
    cmd /c "reg delete `"$($script:HKLM_IDM)`" /f" 2>$null | Out-Null
}

# ── 11. IAS Add AdvIntDriverEnabled2 ──────────────────────────
function Add-IDMKey {
    cmd /c "reg add `"$($script:HKLM_IDM)`" /v `"AdvIntDriverEnabled2`" /t REG_DWORD /d `"1`" /f" 2>$null | Out-Null
}

# ── 12. IAS Internet Check ─────────────────────────────────────
function Test-Internet {
    try {
        if (Test-Connection -ComputerName "internetdownloadmanager.com" -Count 1 -Quiet -ErrorAction SilentlyContinue) { return $true }
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect("internetdownloadmanager.com", 80)
        $r = $tcp.Connected; $tcp.Close(); return $r
    } catch { return $false }
}

# ── 13. IAS Trigger Downloads ──────────────────────────────────
function Start-IDMDownloads {
    if (-not (Test-Path $script:IDMan)) {
        Write-Host "  [!] IDMan.exe not found." -ForegroundColor Red
        return $false
    }
    $file  = "$env:SystemRoot\Temp\temp.png"
    $links = @(
        "https://www.internetdownloadmanager.com/images/idm_box_min.png",
        "https://www.internetdownloadmanager.com/register/IDMlib/images/idman_logos.png",
        "https://www.internetdownloadmanager.com/pictures/idm_about.png"
    )
    $success = $false
    foreach ($link in $links) {
        if (Test-Path $file) { Remove-Item $file -Force -ErrorAction SilentlyContinue }
        Start-Process -FilePath $script:IDMan -ArgumentList "/n /d `"$link`" /p `"$env:SystemRoot\Temp`" /f temp.png" -WindowStyle Hidden
        $attempt = 0
        while ($attempt -lt 20) { Start-Sleep -Seconds 1; $attempt++; if (Test-Path $file) { $success = $true; break } }
        if ($success) { break }
    }
    Start-Sleep -Seconds 3
    Get-Process -Name "IDMan" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    if (Test-Path $file) { Remove-Item $file -Force -ErrorAction SilentlyContinue }
    return $success
}

# ── 14. Backup CLSID keys ─────────────────────────────────────
function Backup-CLSIDKeys {
    if (-not (Test-Path "$env:SystemRoot\Temp")) { New-Item "$env:SystemRoot\Temp" -ItemType Directory -Force | Out-Null }
    $ts   = (Get-Date).ToString("yyyyMMdd-HHmmssfff")
    $path = "$env:SystemRoot\Temp\_Backup_HKCU_CLSID_$ts.reg"
    cmd /c "reg export `"$($script:CLSIDr)`" `"$path`" /y" 2>$null | Out-Null
    if (Test-Path $path) { Write-Host "  Backup saved: $path" -ForegroundColor Gray }
}

# ── 15. Write .reg file ────────────────────────────────────────
function Write-RegFile($name, $content) {
    $path = "$env:TEMP\$name"
    [System.IO.File]::WriteAllText($path, $content, [System.Text.Encoding]::Unicode)
    return $path
}

# ── 16. Cleanup temp files ─────────────────────────────────────
function Clear-TempFiles {
    @('idm_reset.reg','idm_trial.reg','idm_reg.reg') | ForEach-Object {
        Remove-Item "$env:TEMP\$_" -Force -ErrorAction SilentlyContinue
    }
}

# ── 17. .reg file contents ─────────────────────────────────────
$resetReg = @"
Windows Registry Editor Version 5.00

[-HKEY_CURRENT_USER\Software\Classes\CLSID\{7B8E9164-324D-4A2E-A46D-0165FB2000EC}]
[-HKEY_CURRENT_USER\Software\Classes\Wow6432Node\CLSID\{7B8E9164-324D-4A2E-A46D-0165FB2000EC}]
[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{7B8E9164-324D-4A2E-A46D-0165FB2000EC}]
[-HKEY_LOCAL_MACHINE\Software\Classes\Wow6432Node\CLSID\{7B8E9164-324D-4A2E-A46D-0165FB2000EC}]
[-HKEY_CURRENT_USER\Software\Classes\CLSID\{6DDF00DB-1234-46EC-8356-27E7B2051192}]
[-HKEY_CURRENT_USER\Software\Classes\Wow6432Node\CLSID\{6DDF00DB-1234-46EC-8356-27E7B2051192}]
[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{6DDF00DB-1234-46EC-8356-27E7B2051192}]
[-HKEY_LOCAL_MACHINE\Software\Classes\Wow6432Node\CLSID\{6DDF00DB-1234-46EC-8356-27E7B2051192}]
[-HKEY_CURRENT_USER\Software\Classes\CLSID\{D5B91409-A8CA-4973-9A0B-59F713D25671}]
[-HKEY_CURRENT_USER\Software\Classes\Wow6432Node\CLSID\{D5B91409-A8CA-4973-9A0B-59F713D25671}]
[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{D5B91409-A8CA-4973-9A0B-59F713D25671}]
[-HKEY_LOCAL_MACHINE\Software\Classes\Wow6432Node\CLSID\{D5B91409-A8CA-4973-9A0B-59F713D25671}]
[-HKEY_CURRENT_USER\Software\Classes\CLSID\{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}]
[-HKEY_CURRENT_USER\Software\Classes\Wow6432Node\CLSID\{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}]
[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}]
[-HKEY_LOCAL_MACHINE\Software\Classes\Wow6432Node\CLSID\{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}]
[-HKEY_CURRENT_USER\Software\Classes\CLSID\{07999AC3-058B-40BF-984F-69EB1E554CA7}]
[-HKEY_CURRENT_USER\Software\Classes\Wow6432Node\CLSID\{07999AC3-058B-40BF-984F-69EB1E554CA7}]
[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{07999AC3-058B-40BF-984F-69EB1E554CA7}]
[-HKEY_LOCAL_MACHINE\Software\Classes\Wow6432Node\CLSID\{07999AC3-058B-40BF-984F-69EB1E554CA7}]
[HKEY_CURRENT_USER\Software\DownloadManager]
"FName"=-
"LName"=-
"Email"=-
"Serial"=-
[-HKEY_LOCAL_MACHINE\Software\Internet Download Manager]
[-HKEY_LOCAL_MACHINE\Software\Wow6432Node\Internet Download Manager]
"@

$trialReg = @"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\DownloadManager]
"Serial"=""

[HKEY_CURRENT_USER\Software\Classes\CLSID\{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}]
"scansk"=hex(0):91,1d,ac,d6,90,5c,42,ea,ba,1a,ac,08,1a,18,2f,16,2a,a8,0a,aa,24,bf,\
  0c,fc,4e,7b,3b,76,f7,70,93,58,5c,03,03,7e,04,ab,b0,7e,00,00,00,00,00,00,00,\
  00,00,00

[HKEY_CURRENT_USER\Software\Classes\Wow6432Node\CLSID\{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}]
"scansk"=hex(0):91,1d,ac,d6,90,5c,42,ea,ba,1a,ac,08,1a,18,2f,16,2a,a8,0a,aa,24,bf,\
  0c,fc,4e,7b,3b,76,f7,70,93,58,5c,03,03,7e,04,ab,b0,7e,00,00,00,00,00,00,00,\
  00,00,00

[HKEY_CURRENT_USER\Software\DownloadManager]
"scansk"=hex(0):91,1d,ac,d6,90,5c,42,ea,ba,1a,ac,08,1a,18,2f,16,2a,a8,0a,aa,24,bf,\
  0c,fc,4e,7b,3b,76,f7,70,93,58,5c,03,03,7e,04,ab,b0,7e,00,00,00,00,00,00,00,\
  00,00,00

[HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}]
"scansk"=hex(0):91,1d,ac,d6,90,5c,42,ea,ba,1a,ac,08,1a,18,2f,16,2a,a8,0a,aa,24,bf,\
  0c,fc,4e,7b,3b,76,f7,70,93,58,5c,03,03,7e,04,ab,b0,7e,00,00,00,00,00,00,00,\
  00,00,00

[HKEY_LOCAL_MACHINE\Software\Classes\Wow6432Node\CLSID\{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}]
"scansk"=hex(0):91,1d,ac,d6,90,5c,42,ea,ba,1a,ac,08,1a,18,2f,16,2a,a8,0a,aa,24,bf,\
  0c,fc,4e,7b,3b,76,f7,70,93,58,5c,03,03,7e,04,ab,b0,7e,00,00,00,00,00,00,00,\
  00,00,00
"@

$regReg = @"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\DownloadManager]
"FName"="IDM trial reset"
"LName"="(http://bit.ly/IDMresetTrialForum)"
"Email"="your@email.com"
"Serial"="9QNBL-L2641-Y7WVE-QEN3I"

[HKEY_CURRENT_USER\Software\Classes\CLSID\{6DDF00DB-1234-46EC-8356-27E7B2051192}]
"MData"=hex(0):21,9e,ac,77,b5,b5,26,3c,9d,ff,86,40,2d,b9,55,6c,13,17,81,2f,93,54,\
  2e,ab,2c,34,ca,dc,32,1f,a4,b0,c6,cc,4c,83,48,84,2c,1e,68,5f,4d,d7,ac,41,2e,\
  52,5c,6a,4a,78,7c,3b,39,8d,b3,d5,62,d6,a0,e8,12,e5,46,8f,3c,f2,5c,68,ee,21,\
  15,a4,0a,99,ab,bf,d8,2c,5c,77,3b,01,33,e9,9b,4f,12,8e,c4,a7,a1,35,9f,eb,15,\
  a4,0a,99,ab,bf,d8,2c,ef,ac,0d,ee,9b,62,b8,89,1c,42,98,d2,36,ce,b3,9e,e7,56,\
  88,5b,cc,7f,1d,40,34,a2,cd,43,fe,e6,97,15,40,11,6c,23,3f,1a,3c,92,0b,f9,20,\
  e6,17,ac,22,68,8f,45,30,16,84,0d,f4,de,9c,e8,e5,a9,15,5d,d9,1c,22,d2,1b,76,\
  2d,b4,c4,bb,e8,84,71,b7,16,8a,2e,35,a0,a8,66,49,b7,1a,ec,38,0b,5f,4e,35,4e,\
  59,31,63,cd,d2,af,85,4e,90,32,ea,15,44,53,e0,8d,7b,af,34,b8,fe,c8,ec,2c,ef,\
  8a,26,01,77,38,5b,df,31,59,65,36,d8,51,ef,7f,20,6d,43,d6,c2,e8,d6,17,18,16,\
  a4,d0,f3,ea,f7,83,c5,55,00

[HKEY_CURRENT_USER\Software\Classes\Wow6432Node\CLSID\{6DDF00DB-1234-46EC-8356-27E7B2051192}]
"MData"=hex(0):21,9e,ac,77,b5,b5,26,3c,9d,ff,86,40,2d,b9,55,6c,13,17,81,2f,93,54,\
  2e,ab,2c,34,ca,dc,32,1f,a4,b0,c6,cc,4c,83,48,84,2c,1e,68,5f,4d,d7,ac,41,2e,\
  52,5c,6a,4a,78,7c,3b,39,8d,b3,d5,62,d6,a0,e8,12,e5,46,8f,3c,f2,5c,68,ee,21,\
  15,a4,0a,99,ab,bf,d8,2c,5c,77,3b,01,33,e9,9b,4f,12,8e,c4,a7,a1,35,9f,eb,15,\
  a4,0a,99,ab,bf,d8,2c,ef,ac,0d,ee,9b,62,b8,89,1c,42,98,d2,36,ce,b3,9e,e7,56,\
  88,5b,cc,7f,1d,40,34,a2,cd,43,fe,e6,97,15,40,11,6c,23,3f,1a,3c,92,0b,f9,20,\
  e6,17,ac,22,68,8f,45,30,16,84,0d,f4,de,9c,e8,e5,a9,15,5d,d9,1c,22,d2,1b,76,\
  2d,b4,c4,bb,e8,84,71,b7,16,8a,2e,35,a0,a8,66,49,b7,1a,ec,38,0b,5f,4e,35,4e,\
  59,31,63,cd,d2,af,85,4e,90,32,ea,15,44,53,e0,8d,7b,af,34,b8,fe,c8,ec,2c,ef,\
  8a,26,01,77,38,5b,df,31,59,65,36,d8,51,ef,7f,20,6d,43,d6,c2,e8,d6,17,18,16,\
  a4,d0,f3,ea,f7,83,c5,55,00

[HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{6DDF00DB-1234-46EC-8356-27E7B2051192}]
"MData"=hex(0):21,9e,ac,77,b5,b5,26,3c,9d,ff,86,40,2d,b9,55,6c,13,17,81,2f,93,54,\
  2e,ab,2c,34,ca,dc,32,1f,a4,b0,c6,cc,4c,83,48,84,2c,1e,68,5f,4d,d7,ac,41,2e,\
  52,5c,6a,4a,78,7c,3b,39,8d,b3,d5,62,d6,a0,e8,12,e5,46,8f,3c,f2,5c,68,ee,21,\
  15,a4,0a,99,ab,bf,d8,2c,5c,77,3b,01,33,e9,9b,4f,12,8e,c4,a7,a1,35,9f,eb,15,\
  a4,0a,99,ab,bf,d8,2c,ef,ac,0d,ee,9b,62,b8,89,1c,42,98,d2,36,ce,b3,9e,e7,56,\
  88,5b,cc,7f,1d,40,34,a2,cd,43,fe,e6,97,15,40,11,6c,23,3f,1a,3c,92,0b,f9,20,\
  e6,17,ac,22,68,8f,45,30,16,84,0d,f4,de,9c,e8,e5,a9,15,5d,d9,1c,22,d2,1b,76,\
  2d,b4,c4,bb,e8,84,71,b7,16,8a,2e,35,a0,a8,66,49,b7,1a,ec,38,0b,5f,4e,35,4e,\
  59,31,63,cd,d2,af,85,4e,90,32,ea,15,44,53,e0,8d,7b,af,34,b8,fe,c8,ec,2c,ef,\
  8a,26,01,77,38,5b,df,31,59,65,36,d8,51,ef,7f,20,6d,43,d6,c2,e8,d6,17,18,16,\
  a4,d0,f3,ea,f7,83,c5,55,00

[HKEY_LOCAL_MACHINE\Software\Classes\Wow6432Node\CLSID\{6DDF00DB-1234-46EC-8356-27E7B2051192}]
"MData"=hex(0):21,9e,ac,77,b5,b5,26,3c,9d,ff,86,40,2d,b9,55,6c,13,17,81,2f,93,54,\
  2e,ab,2c,34,ca,dc,32,1f,a4,b0,c6,cc,4c,83,48,84,2c,1e,68,5f,4d,d7,ac,41,2e,\
  52,5c,6a,4a,78,7c,3b,39,8d,b3,d5,62,d6,a0,e8,12,e5,46,8f,3c,f2,5c,68,ee,21,\
  15,a4,0a,99,ab,bf,d8,2c,5c,77,3b,01,33,e9,9b,4f,12,8e,c4,a7,a1,35,9f,eb,15,\
  a4,0a,99,ab,bf,d8,2c,ef,ac,0d,ee,9b,62,b8,89,1c,42,98,d2,36,ce,b3,9e,e7,56,\
  88,5b,cc,7f,1d,40,34,a2,cd,43,fe,e6,97,15,40,11,6c,23,3f,1a,3c,92,0b,f9,20,\
  e6,17,ac,22,68,8f,45,30,16,84,0d,f4,de,9c,e8,e5,a9,15,5d,d9,1c,22,d2,1b,76,\
  2d,b4,c4,bb,e8,84,71,b7,16,8a,2e,35,a0,a8,66,49,b7,1a,ec,38,0b,5f,4e,35,4e,\
  59,31,63,cd,d2,af,85,4e,90,32,ea,15,44,53,e0,8d,7b,af,34,b8,fe,c8,ec,2c,ef,\
  8a,26,01,77,38,5b,df,31,59,65,36,d8,51,ef,7f,20,6d,43,d6,c2,e8,d6,17,18,16,\
  a4,d0,f3,ea,f7,83,c5,55,00

[HKEY_CURRENT_USER\Software\DownloadManager]
"scansk"=hex(0):6f,4e,79,b5,cc,8b,50,bb,f4,b7,e2,6d,2e,38,d2,8b,ad,10,0b,03,a6,\
  1b,53,30,6b,b8,8b,92,d6,04,22,c7,55,b9,a5,33,4d,a8,4e,9b,00,00,00,00,00,00,\
  00,00,00,00

[HKEY_CURRENT_USER\Software\Classes\CLSID\{7B8E9164-324D-4A2E-A46D-0165FB2000EC}]
"scansk"=hex(0):6f,4e,79,b5,cc,8b,50,bb,f4,b7,e2,6d,2e,38,d2,8b,ad,10,0b,03,a6,\
  1b,53,30,6b,b8,8b,92,d6,04,22,c7,55,b9,a5,33,4d,a8,4e,9b,00,00,00,00,00,00,\
  00,00,00,00

[HKEY_CURRENT_USER\Software\Classes\Wow6432Node\CLSID\{7B8E9164-324D-4A2E-A46D-0165FB2000EC}]
"scansk"=hex(0):6f,4e,79,b5,cc,8b,50,bb,f4,b7,e2,6d,2e,38,d2,8b,ad,10,0b,03,a6,\
  1b,53,30,6b,b8,8b,92,d6,04,22,c7,55,b9,a5,33,4d,a8,4e,9b,00,00,00,00,00,00,\
  00,00,00,00

[HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{7B8E9164-324D-4A2E-A46D-0165FB2000EC}]
"scansk"=hex(0):6f,4e,79,b5,cc,8b,50,bb,f4,b7,e2,6d,2e,38,d2,8b,ad,10,0b,03,a6,\
  1b,53,30,6b,b8,8b,92,d6,04,22,c7,55,b9,a5,33,4d,a8,4e,9b,00,00,00,00,00,00,\
  00,00,00,00

[HKEY_LOCAL_MACHINE\Software\Classes\Wow6432Node\CLSID\{7B8E9164-324D-4A2E-A46D-0165FB2000EC}]
"scansk"=hex(0):6f,4e,79,b5,cc,8b,50,bb,f4,b7,e2,6d,2e,38,d2,8b,ad,10,0b,03,a6,\
  1b,53,30,6b,b8,8b,92,d6,04,22,c7,55,b9,a5,33,4d,a8,4e,9b,00,00,00,00,00,00,\
  00,00,00,00
"@

# ── 18. Core Functions (lock ছাড়া) ────────────────────────────

function Invoke-Reset {
    Write-Host "  Searching dynamic GUID..." -ForegroundColor Gray
    $script:dynamicKey = Find-DynamicKey
    if ($script:dynamicKey -and ($script:allkeys -notcontains $script:dynamicKey)) {
        $script:allkeys += $script:dynamicKey
        Write-Host "  Dynamic GUID: $($script:dynamicKey)" -ForegroundColor Gray
    }
    Write-Host "  Unlocking registry keys..." -ForegroundColor Gray
    Unlock-RegKeys
    Write-Host "  Clearing IDM data..." -ForegroundColor Gray
    $p = Write-RegFile "idm_reset.reg" $resetReg
    cmd /c "reg import `"$p`"" 2>$null
    if ($script:dynamicKey) {
        @("HKCU:\Software\Classes\CLSID\$($script:dynamicKey)",
          "HKCU:\Software\Classes\Wow6432Node\CLSID\$($script:dynamicKey)",
          "HKLM:\Software\Classes\CLSID\$($script:dynamicKey)",
          "HKLM:\Software\Classes\Wow6432Node\CLSID\$($script:dynamicKey)") | ForEach-Object {
            Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-Trial {
    Invoke-Reset
    Write-Host "  Applying fresh trial data..." -ForegroundColor Gray
    $p = Write-RegFile "idm_trial.reg" $trialReg
    cmd /c "reg import `"$p`"" 2>$null
    # লক নেই
}

function Invoke-FreezeTrial {
    if (-not (Test-Path $script:IDMan)) {
        Write-Host "  [!] IDM not found. Please install IDM first." -ForegroundColor Red
        return
    }
    Write-Host "  Checking internet connection..." -ForegroundColor Gray
    if (-not (Test-Internet)) {
        Write-Host "  [!] Cannot connect to internetdownloadmanager.com. Internet required." -ForegroundColor Red
        return
    }
    Write-Host "  Stopping IDM..." -ForegroundColor Yellow
    Get-Process -Name "IDMan" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Write-Host "  Creating registry backup..." -ForegroundColor Gray
    Backup-CLSIDKeys
    Write-Host "  Deleting trial tracking values..." -ForegroundColor Gray
    Remove-TrialValues
    Add-IDMKey
    Write-Host "  Triggering IDM downloads to generate new keys (please wait)..." -ForegroundColor Yellow
    $ok = Start-IDMDownloads
    if (-not $ok) {
        Write-Host "  [!] Download trigger failed. Check IDM is working properly." -ForegroundColor Red
        return
    }
    Write-Host ""
    Write-Host "  [OK] Freeze Trial complete! Start IDM now." -ForegroundColor Green
    # লক নেই
}

function Invoke-Register($fname) {
    Invoke-Reset
    Write-Host "  Applying registration data..." -ForegroundColor Gray
    $p = Write-RegFile "idm_reg.reg" $regReg
    cmd /c "reg import `"$p`"" 2>$null
    if ($script:dynamicKey) {
        @("HKCU:\Software\Classes\CLSID\$($script:dynamicKey)",
          "HKCU:\Software\Classes\Wow6432Node\CLSID\$($script:dynamicKey)",
          "HKLM:\Software\Classes\CLSID\$($script:dynamicKey)",
          "HKLM:\Software\Classes\Wow6432Node\CLSID\$($script:dynamicKey)") | ForEach-Object {
            if (-not (Test-Path $_)) { New-Item $_ -Force -ErrorAction SilentlyContinue | Out-Null }
        }
    }
    cmd /c "reg add `"HKCU\Software\DownloadManager`" /v `"FName`" /t `"REG_SZ`" /d `"$fname`" /f" 2>$null
    # লক নেই
}

# ── 19. Main Menu ──────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "  =============================================" -ForegroundColor Cyan
Write-Host "    IDM Trial Reset Tool (Online Version)     " -ForegroundColor Cyan
Write-Host "  =============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  [1]  Reset Trial    (fresh 30-day trial)"        -ForegroundColor White
Write-Host "  [2]  Freeze Trial   (reset trial for lifetime)"  -ForegroundColor White
Write-Host "  [3]  Register       (simulate registered copy)"  -ForegroundColor White
Write-Host "  [4]  Exit"                                        -ForegroundColor White
Write-Host ""

$choice = Read-Host "  Select option"

switch ($choice) {
    '1' {
        Write-Host ""
        Write-Host "  Stopping IDM..." -ForegroundColor Yellow
        Stop-Process -Name "IDMan" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        Write-Host "  Running Trial Reset..." -ForegroundColor Yellow
        Invoke-Trial; Clear-TempFiles
        Write-Host ""
        Write-Host "  [OK] Trial reset complete! Start IDM now." -ForegroundColor Green
    }
    '2' {
        Write-Host ""
        Write-Host "  Running Freeze Trial..." -ForegroundColor Yellow
        Write-Host "  Note: Internet connection required." -ForegroundColor Gray
        Write-Host ""
        Invoke-FreezeTrial; Clear-TempFiles
    }
    '3' {
        Write-Host ""
        $fname = Read-Host "  Enter name to register with (default: IDM trial reset)"
        if ([string]::IsNullOrWhiteSpace($fname)) { $fname = "IDM trial reset" }
        Write-Host ""
        Write-Host "  Stopping IDM..." -ForegroundColor Yellow
        Stop-Process -Name "IDMan" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        Write-Host "  Running Register Simulation..." -ForegroundColor Yellow
        Invoke-Register $fname; Clear-TempFiles
        Write-Host ""
        Write-Host "  [OK] Registered as: $fname" -ForegroundColor Green
        Write-Host "  Start IDM now." -ForegroundColor Green
    }
    '4' { Write-Host "  Exiting..." -ForegroundColor Gray; exit }
    default { Write-Host "  Invalid option." -ForegroundColor Red }
}

Write-Host ""
Write-Host "  Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
