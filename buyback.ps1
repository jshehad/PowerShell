<# First :
         -> Get Hostname & Mac address and store it into a CSV file 
		 -> Copy User files into a new folder
#>

# Storing MAC address with Computer Name
$hostname = hostname
$mac = ((Get-NetAdapter | Where Name -match 'Wi-Fi').macaddress) -replace '[-]', ''
$hostname + ',' + $mac >> D:\RemoveFromAD.csv # This could be chanage to the share drive instead

# Restoring Original Windows License
[string]$key = wmic path SoftwareLicensingService get OA3xOriginalProductKey
[string]$keyTrimed = $key.Trim('OA3xOriginalProductKey           ')
Invoke-Command -ScriptBlock {& cmd /c "changepk.exe /ProductKey $keyTrimed"}
Start-Sleep -Seconds 15

# Creating Directories
[string]$path = "C:\Users\LCPSAdmin\Desktop\backupfiles"
New-Item -Path "C:\Users\LCPSAdmin\Desktop" -Name "backupfiles" -ItemType "directory"
New-Item -Path $path -Name "Documents" -ItemType "directory"
New-Item -Path $path -Name "Downloads" -ItemType "directory"
New-Item -Path $path -Name "Pictures" -ItemType "directory"
New-Item -Path $path -Name "Desktop" -ItemType "directory"

Write-Host "`n`tUsers Profile Available on this Computer`n"
(Get-ChildItem -Path C:\Users).Name

# Validate Path
$user = $false
while ($user -eq $false){
Write-Host "`n"
[string]$userAccount = Read-host 'Please enter User account name'
$pathSample = "C:\users\$userAccount\"
$testPath = Test-Path -Path $pathSample

if($testPath -eq $true){
    $user = $true
}
else{write-host "try again"}
}

Write-Host "`nFile Path Found! Now Writing Files ...`n"

# Coping Files
Copy-Item -Path "C:\Users\$userAccount\Documents\*" -Destination "$path\Documents" -Recurse
Copy-Item -Path "C:\Users\$userAccount\Downloads\*" -Destination "$path\Downloads" -Recurse
Copy-Item -Path "C:\Users\$userAccount\Pictures\*" -Destination "$path\Pictures" -Recurse
Copy-Item -Path "C:\Users\$userAccount\Desktop\*" -Destination "$path\Desktop" -Recurse

<# Second : 
		-> Modify local user account Password
		-> Rename a current local user account
				#Rename-LocalUser -Name "LCPSAdmin" -NewName "User"
		-> Remove a second local user account
				#Remove-LocalUser -Name "Manager"
				
#>
Set-LocalUser -Name "LCPSAdmin" -Password ([securestring]::new())
Rename-LocalUser -Name "LCPSAdmin" -NewName "User"
Remove-LocalUser -Name "Manager"

<# Third : 
		 -> Rename, unjoin PC from the domain, and Restart
#>

# Uninstalling Microsoft Office 16
Set-Location -Path 'C:\Program Files (x86)\Microsoft Office\Office16'
$office = ((cscript ospp.vbs /dstatus) -match "key")
$officeKey = $office.substring($office.Length+43)
cscript ospp.vbs /unpkey:$officeKey
Start-Sleep -Seconds 15

# Uninstalling Programs
if(((Get-Package).name).contains("Ninite Agent (MSI)") -eq $true){
    Uninstall-Package -Name "Ninite Agent (MSI)" -Force
    Start-Sleep -Seconds 15
}

Invoke-Command -ScriptBlock {& 'C:\Program Files (x86)\TeamViewer\uninstall.exe' /S}
Start-Sleep -Seconds 15

# Unjoining PC from the Domain
$admin = Read-Host 'Please enter your Admin Username'
Remove-Computer -ComputerName $hostname -UnjoinDomainCredential CAMPUS.LCPS\$admin -PassThru -Force
Start-Sleep -Seconds 10

# Renaming Computer Name
# Rename-Computer -ComputerName $hostname -NewName "LocalUser" -LocalCredential User01 -Force

# Resetting All Local Security Policies to Default
# Invoke-Command -ScriptBlock {cmd /c secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb /verbose}

# Local Security Policies - Interactive logon: Don't display last signed-in - Default: Disable.
# Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name dontdisplaylastusername -Value 0
# Start-Sleep -Seconds 10

<#

# Resetting All Group Policies to Default
Invoke-Command -ScriptBlock {cmd /c RD /S /Q "%WinDir%\System32\GroupPolicyUsers"}
Invoke-Command -ScriptBlock {cmd /c RD /S /Q "%WinDir%\System32\GroupPolicy"}
Invoke-Command -ScriptBlock {cmd /c gpupdate /force}

#>

# Wait
Write-Host "`nRestart will begin in 10 seconds`n"
Start-Sleep -Seconds 10

# Restart Computer
Restart-Computer -Force