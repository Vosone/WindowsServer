# Zertifikat erstellen
$cert = New-SelfSignedCertificate -Subject "CN=10.0.0.125" -CertStoreLocation "Cert:\LocalMachine\My"

# HTTPS Listener erstellen
New-Item -Path WSMan:\Localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force

# Firewallregel für HTTPS hinzufügen
New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow

# WinRM-Service konfigurieren
Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true

Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false

Set-Item -Path WSMan:\localhost\Service\EnableCompatibilityHttpListener -Value $false
Set-Item -Path WSMan:\localhost\Service\EnableCompatibilityHttpsListener -Value $false

# Benutzer erstellen
New-LocalUser -Name malon -Description "Ansible User"

# Benutzergruppe hinzufügen
Add-LocalGroupMember -Group "Administrators" -Member "malon"
Add-LocalGroupMember -Group "Remote Management Users" -Member "malon"

# Berechtigungen setzen
Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurityDescriptorUI