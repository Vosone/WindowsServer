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

$cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 "cert.pem"

$store_name = [System.Security.Cryptography.X509Certificates.StoreName]::Root
$store_location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
$store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $store_name, $store_location
$store.Open("MaxAllowed")
$store.Add($cert)
$store.Close()

$cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 "cert.pem"

$store_name = [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople
$store_location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
$store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $store_name, $store_location
$store.Open("MaxAllowed")
$store.Add($cert)
$store.Close()

$username = "malon"
$password = ConvertTo-SecureString -String "Sauber88$" -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password

# This is the issuer thumbprint which in the case of a self generated cert
# is the public key thumbprint, additional logic may be required for other
# scenarios
$thumbprint = (Get-ChildItem -Path cert:\LocalMachine\root | Where-Object { $_.Subject -eq "CN=$username" }).Thumbprint

New-Item -Path WSMan:\localhost\ClientCertificate `
    -Subject "$username@localhost" `
    -URI * `
    -Issuer $thumbprint `
    -Credential $credential `
    -Force