# Requires Admin Privileges

# --- CONFIGURATION ---
$DriverFileName = "AVeryNormalDriver.sys" 
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$DriverSysSource = Join-Path $ScriptDir $DriverFileName
$DriverSysDest   = "C:\Windows\System32\drivers\$DriverFileName"
$ServiceName = "AVeryNormalDriver"
$ServiceDisplayName = "The most normal driver ever"
$FlagDir = "C:\Secrets"
$FlagPath = Join-Path $FlagDir "flag.txt"
$FlagContent = "flag{n0t_s0_n0rm4l_dr1v3r_uR_2_1337}"

# --- 0. Enable Test Mode for Unsigned Drivers ---
Write-Host "`n[+] Enabling Test Signing Mode..." -ForegroundColor Cyan
bcdedit /set testsigning on
bcdedit /set nointegritychecks on

# --- 1. Copy the .sys driver to the system directory ---
Write-Host "[+] Copying driver to system drivers directory..." -ForegroundColor Cyan
if (-not (Test-Path $DriverSysSource)) {
    Write-Error "Driver file not found at: $DriverSysSource"
    exit 1
}
Copy-Item -Path $DriverSysSource -Destination $DriverSysDest -Force

# --- 2. Create a kernel-mode service for the driver ---
Write-Host "[+] Creating kernel driver service..." -ForegroundColor Cyan
sc.exe create $ServiceName binPath= $DriverSysDest type= kernel start= auto DisplayName= "$ServiceDisplayName"

# --- 3. Create a privileged-only directory and flag file ---
Write-Host "[+] Creating privileged directory and writing flag..." -ForegroundColor Cyan
if (-not (Test-Path $FlagDir)) {
    New-Item -ItemType Directory -Path $FlagDir -Force
}

# Set ACL: Only Administrators and SYSTEM
$acl = Get-Acl $FlagDir
$acl.SetAccessRuleProtection($true, $false)  # Disable inheritance
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")

$acl.AddAccessRule($adminRule)
$acl.AddAccessRule($systemRule)

Set-Acl -Path $FlagDir -AclObject $acl

# Write the flag
Set-Content -Path $FlagPath -Value $FlagContent -Encoding ASCII

Write-Host "`n[+] Driver installed and flag dropped at $FlagPath" -ForegroundColor Green
Write-Host "[!] You must reboot for test signing mode to activate and the driver to load." -ForegroundColor Yellow
$reboot = Read-Host "Reboot now? (y/n)"
if ($reboot -eq "y") {
    Restart-Computer
}
