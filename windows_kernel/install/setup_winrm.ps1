# Requires Admin Privileges

# Create Local User
$password = ConvertTo-SecureString 'u1J2&o2k(fy~-}n^k}*a%T]D' -AsPlainText -Force 
New-LocalUser -Name "greynoise" -FullName "GreyNoise" -Password $password -AccountNeverExpires -UserMayNotChangePassword -PasswordNeverExpires

# Add user to Remote Management so they can authenticate
Add-LocalGroupMember -Group "Remote Management Users" -Member "greynoise"

# Start WinRM Service
# Set to automatic startup
# Create a listener for default protocol (HTTP)
# Configure Firewall to allow WinRM traffic
winrm quickconfig -quiet

# Enable WinRM service
Enable-PSRemoting -Force

# Change the RemoteHost Scope from "LocalSubnet" to "any" for firewall rule
Set-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -RemoteAddress Any

# Allow basic authentication
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true

# Allow unencrypted connection (optional for testing)
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true

# Set firewall rule
Enable-NetFirewallRule -Name "WINRM-HTTP-In-TCP"

# Allow all Hosts (clients allowed to attempt authentication)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force

