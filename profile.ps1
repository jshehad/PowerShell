# -------------------------------------------------------------------------------------------------------------------
# 
# Created By: Jihad Shehadeh
#
# Instructions:
#				Step 1: Create and Move file to the following directory
#						Description						Path
#					All Users, All Hosts			$PSHOME\Profile.ps1
#					All Users, Current Host			$PSHOME\Microsoft.PowerShell_profile.ps1
#					Current User, All Hosts			$Home\[My ]Documents\PowerShell\Profile.ps1
#					Current user, Current Host		$Home\[My ]Documents\PowerShell\Microsoft.PowerShell_profile.ps1
# 				
#				Step 2: Open PowerShell in Administrator mode
#				Step 3: Run "Set-ExecutionPolicy RemoteSigned"
#				Step 4: Exit out of Administartor mode and enter User mode
#				Step 5: Start using the functions below
#
# -------------------------------------------------------------------------------------------------------------------


# -------------------------------------------
# Function Name: p
# Description: Test if a computer is online (quick ping replacement)
# -------------------------------------------
function p {
    param($computername)
    return (test-connection $computername -count 1 -quiet)
}

# -------------------------------------------
# Function Name: Get-NAT
# Description: Takes one argument which is the Computer Name and gives you the Network info 
# -------------------------------------------
function Get-NIC { 
    param ($ComputerName) 
     
    If(p($ComputerName) -eq $true){
		$colItems = get-wmiobject -class "Win32_NetworkAdapterConfiguration" -computername $ComputerName `
		| Where{$_.IpEnabled -Match "True"} 
		foreach ($objItem in $colItems) {  
			$objItem | select Description,MACAddress,IPAddress
	     }
    }
    Else{
         Write-Host "`n`tUser is not Online`n"
    }
}

# -------------------------------------------
# Function Name: Get-LoggedIn
# Description: Return the current logged-in user of a remote machine.
# -------------------------------------------
function Get-LoggedIn {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory=$True)]
    [string[]]$computername
  )

  foreach ($pc in $computername){
    $logged_in = (gwmi win32_computersystem -COMPUTER $pc).username
    $name = $logged_in.split("\")[1]
    "{0}: {1}" -f $pc,$name
  }
}

function Find-UserName{param([Parameter(Position=0)][string]$FirstName, [Parameter(Position=1)][string]$Middle, [Parameter(Position=2)][string]$LastName)
	
	if($PSBoundParameters.count -eq 3){
            
            $UserName = $LastName.Substring(0,6) + $FirstName[0] + $Middle[0]

      }
	elseif($PSBoundParameters.count -eq 2){
        
        $UserName = $Middle.Substring(0,6) + $FirstName[0]

    }

	Get-ComputerName($UserName)
}

# -------------------------------------------
# Function Name: Get-ComputerName 
# Description: Searches username  and return Users Computer Name
# -------------------------------------------
function Get-ComputerName{param ([string]$UserInput)

	$OUs = "DC=CAMPUS,DC=LCPS"
	$AllCom = Get-ADComputer -Filter * -Searchbase $OUs | select Name
		foreach($Com in $AllCom){
			[string]$Check = $Com.Name.Split("-")[1]
			if($Check -eq $UserInput){
				$Com
				 }
		
	}
}

# -------------------------------------------
# Function Name: Get-Uptime
# Description: Calculate and display system uptime on a local machine or remote machine.
# -------------------------------------------
function Get-Uptime {
    [CmdletBinding()]
    param (
        [string]$ComputerName = 'localhost'
    )
    
    foreach ($Computer in $ComputerName){
        $pc = $computername
        $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computername
        $diff = $os.ConvertToDateTime($os.LocalDateTime) - $os.ConvertToDateTime($os.LastBootUpTime)

        $properties = @{
            'ComputerName' = $pc;
            'UptimeDays' = $diff.Days;
            'UptimeHours' = $diff.Hours;
            'UptimeMinutes' = $diff.Minutes;
            'UptimeSeconds' = $diff.Seconds;
        }
        $obj = New-Object -TypeName PSObject -Property $properties

        Write-Output $obj
    }
       
 }

# -------------------------------------------
# Function Name: Get-HWVersion
# Description: Retreives device name, driver date, and driver version
# -------------------------------------------
function Get-HWVersion($computer, $name) {

     $pingresult = Get-WmiObject win32_pingstatus -f "address='$computer'"
     if($pingresult.statuscode -ne 0) { return }

     gwmi -Query "SELECT * FROM Win32_PnPSignedDriver WHERE DeviceName LIKE '%$name%'" -ComputerName $computer | 
           Sort DeviceName | 
           Select @{Name="Server";Expression={$_.__Server}}, DeviceName, `
		   @{Name="DriverDate";Expression={[System.Management.ManagementDateTimeconverter]::ToDateTime($_.DriverDate).ToString("MM/dd/yyyy")}}, DriverVersion
}

# -------------------------------------------
# Function Name: Get-ActCom
# Description: Retreives device name, Operating System, and Last LoggedIn Info.
# 1st argument takes the school's initial ex. T for Trevilians and TJ for Thomas Jefferson
# 2nd argument is used to subtract the number of days from today
# 2nd argument can be $null to get all of the Computers in school
# UPADTED : accpets 4 characher for 1st argument
# -------------------------------------------
function Get-ActCom([string]$school,$days){    
    if($days -eq $null){
        $results = Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate | Select Name,OperatingSystem,LastLogonDate | Sort Name
                
        $CharCount = ($school).Length

        foreach ($Com in $results){
	        if($CharCount = 1 -And  ($Com.Name[1] -match "\d+")){
                [string]$Check = $Com.Name.substring(0, 1)
                if($Check -eq $school){
		            $Com
		        }
            }

            ElseIf($CharCount = 2 -And ($Com.Name[2] -match ("\d+"))){
                [string]$Check = $Com.Name.substring(0, 2)
                if($Check -eq $school){
		            $Com
		        }
            }
            ElseIf($CharCount = 4 -And ($Com.Name[4] -match  ".")){
                    [string]$Check = $Com.Name.substring(0,4)
                    if($Check -eq $school){
                        $Com
                    }
                }

        }
    
    }
    Else{
        $cutoff = (Get-Date).AddDays(-($days))

        $filter = "LastLogonDate -gt '$cutoff'"

        $results = Get-ADComputer -Filter $filter -Properties OperatingSystem,LastLogonDate `
		| Select Name,OperatingSystem,LastLogonDate | Sort Name
                
        $CharCount = ($school).Length

            foreach ($Com in $results){
	            if($CharCount = 1 -And  ($Com.Name[1] -match "\d+")){
                    [string]$Check = $Com.Name.substring(0, 1)
                    if($Check -eq $school){
		                $Com
		            }
                }
                ElseIf($CharCount = 2 -And ($Com.Name[2] -match "\d+")){
                    [string]$Check = $Com.Name.substring(0, 2)
                    if($Check -eq $school){
		                $Com
		            }
                }
                ElseIf($CharCount = 4 -And ($Com.Name[4] -match  ".")){
                    [string]$Check = $Com.Name.substring(0,4)
                    if($Check -eq $school){
                        $Com
                    }
                }

            }
        }
}

# -------------------------------------------
# Function Name: Add-MacAuth4Staff
# Description: Add Mac address to AD 
# 1st argument defines what group to place the user in. Either Staff or BYOD
# 2nd argument takes the MAC Address
# 3rd argument is for the Description or Name of the User
# -------------------------------------------
function Add-MacAuth4Staff { param([string]$type,[string]$MacID,[string]$StaffName)

    [string]$BlankField = $MacID                                  
    [string]$Description = $StaffName       
    $Password = ConvertTo-SecureString -String $BlankField -AsPlainText -Force
    
    If((($MacID).length -eq 12) -and ($MacID -match '([a-f0-9]{12})')){
 
        If($type -eq "Staff") {
            $OU = "OU=MacAuth_Staff,OU=MacAuthenticated,DC=CAMPUS,DC=LCPS"
               
            New-ADUser -Name "$BlankField" -DisplayName "$BlankField" -SamAccountName $BlankField  -GivenName "$BlankField" -UserPrincipalName "$BlankField"`
		    -Description $StaffName -AccountPassword $Password -Enabled $true -Path "$OU" -ChangePasswordAtLogon $false `
		    -PasswordNeverExpires $true -CannotChangePassword $true -server CAMPUS.LCPS

            Write-Host "Successfully Upload"

        }ElseIf ($type -eq "BYOD") {
            $OU = "OU=MacAuth_Staff_BYOD,OU=MacAuth_Staff,OU=MacAuthenticated,DC=CAMPUS,DC=LCPS"
               
            New-ADUser -Name "$BlankField" -DisplayName "$BlankField" -SamAccountName $BlankField  -GivenName "$BlankField" -UserPrincipalName "$BlankField"`
		    -Description $StaffName -AccountPassword $Password -Enabled $true -Path "$OU" -ChangePasswordAtLogon $false `
		    -PasswordNeverExpires $true -CannotChangePassword $true -server CAMPUS.LCPS

            Write-Host "Successfully Upload"

        }Else {
            Write-Warning -Message "Invalid input"
			return
            }
    }
    Else{Write-Host "MAC ID must not have been correctly entered!"}
}

# -------------------------------------------
# Function Name: Get-ServerList
# Description: returns available servers in AD
# No arguments needed
# -------------------------------------------
function Get-ServerList{ 

        $results = Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate | `
                    Select Name,OperatingSystem,LastLogonDate | Sort Name

        foreach($com in $results){
            if($com.OperatingSystem -match 'Server'){
            $com
            }
        }


}

# -------------------------------------------
# Function Name: dhcp-lease
# Description: Helps you locate devices IP address by entering the MAC address and School location
# 1st argument Mac address (Format 00-00-00-00-00-00) 
# 2nd argument School
# -------------------------------------------
function dhcp-lease {param([string]$MacID, [string]$School)

    If($School -eq "TJES"){
        [string]$locate = "tjes2012r2dc"
    }
    ElseIf($School -eq "TES"){
        [string]$locate = "tes2012r2dc"
    }
    ElseIf($School -eq "MNES"){
        [string]$locate = "mnesdc"
    }
    ElseIf($School -eq "JES"){
        [string]$locate = "jes2012r2dc"
    }
    ElseIf($School -eq "LCHS"){
        [string]$locate = "lchs-dc"
    }
	ElseIf($School -eq "LCMS"){
        [string]$locate = "lcpsdc"
    }
    $Dhcp = Get-DhcpServerv4Scope -ComputerName $locate | Get-DhcpServerv4Lease -ComputerName $locate 

    foreach($DL in $Dhcp){
        if($DL.clientid -eq $MacID){
            $DL  
        }
        
    }
}

function dhcp-iplease {param($IP, [string]$School)

    If($School -eq "TJES"){
        [string]$locate = "tjes2012r2dc"
    }
    ElseIf($School -eq "TES"){
        [string]$locate = "tes2012r2dc"
    }
    ElseIf($School -eq "MNES"){
        [string]$locate = "mnesdc"
    }
    ElseIf($School -eq "JES"){
        [string]$locate = "jes2012r2dc"
    }
    ElseIf($School -eq "LCHS"){
        [string]$locate = "lchs-dc"
    }
	ElseIf($School -eq "LCMS"){
        [string]$locate = "lcpsdc"
    }
    $Dhcp = Get-DhcpServerv4Scope -ComputerName $locate | Get-DhcpServerv4Lease -ComputerName $locate 

    foreach($DL in $Dhcp){
        if($DL.Scopeid -eq $IP){
            $DL  
        }
        
    }
}

function Send-Message {param($ComputerName, [string]$Subject, [string]$Body)
	
	$message = Send-RDUserMessage -HostServer $ComputerName -UnifiedSessionID 1 -MessageTitle $Subject -MessageBody $Body

}