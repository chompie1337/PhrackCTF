# Phrack CTF 2025 Windows Kernel Challenge

## Infra Installation Instructions

From the install directory, run:

`install_vnd.ps1`

Type y to reboot. 

This script will turn on test mode (needed in order to load an unsigned driver) and install the driver service to load on startup.

Once rebooted, you can ensure the driver is loaded by running (in Powershell):

```Get-WmiObject Win32_SystemDriver | Where-Object { $_.State -eq "Running" } | Select-Object Name, DisplayName, PathName```

You should see the `AVeryNormalDriver` service running. 

To enable the WinRM service (for remote login) and create an unprivileged user, run:

`install_vnd.ps1`

## Flag 

The flag is stored in `C:\Secrets\flag.txt`, which is only readable by Administrator and SYSTEM.

## Connect

To test the connection and login to the machine run:

```sudo docker run --rm -it oscarakaelvis/evil-winrm -i <Ip address> -u greynoise -p 'u1J2&o2k(fy~-}n^k}*a%T]D'```
