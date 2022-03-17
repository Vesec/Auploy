


$error.clear()

function Get-UsernameInput{

$Global:AuployPath = Read-Host "


 █     █░ ██░ ██  ▒█████      ▄▄▄       ██▀███  ▓█████    ▓██   ██▓ ▒█████   █    ██ 
▓█░ █ ░█░▓██░ ██▒▒██▒  ██▒   ▒████▄    ▓██ ▒ ██▒▓█   ▀     ▒██  ██▒▒██▒  ██▒ ██  ▓██▒
▒█░ █ ░█ ▒██▀▀██░▒██░  ██▒   ▒██  ▀█▄  ▓██ ░▄█ ▒▒███        ▒██ ██░▒██░  ██▒▓██  ▒██░
░█░ █ ░█ ░▓█ ░██ ▒██   ██░   ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓█  ▄      ░ ▐██▓░▒██   ██░▓▓█  ░██░
░░██▒██▓ ░▓█▒░██▓░ ████▓▒░    ▓█   ▓██▒░██▓ ▒██▒░▒████▒     ░ ██▒▓░░ ████▓▒░▒▒█████▓ 
░ ▓░▒ ▒   ▒ ░░▒░▒░ ▒░▒░▒░     ▒▒   ▓▒█░░ ▒▓ ░▒▓░░░ ▒░ ░      ██▒▒▒ ░ ▒░▒░▒░ ░▒▓▒ ▒ ▒ 
  ▒ ░ ░   ▒ ░▒░ ░  ░ ▒ ▒░      ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ░  ░    ▓██ ░▒░   ░ ▒ ▒░ ░░▒░ ░ ░ 
  ░   ░   ░  ░░ ░░ ░ ░ ▒       ░   ▒     ░░   ░    ░       ▒ ▒ ░░  ░ ░ ░ ▒   ░░░ ░ ░ 
    ░     ░  ░  ░    ░ ░           ░  ░   ░        ░  ░    ░ ░         ░ ░     ░     
                                                           ░ ░                       

*Could Not find Path to Auploy*

Expected Path $DesktopPath

Enter Enter Path To Folder Containing Auploy"

}

$DesktopPath = [Environment]::GetFolderPath("Desktop")

$error.clear()

try{

$Global:OUFile = Import-Csv "$DesktopPath\Auploy\Settings\OU\OU.csv"
$Global:UserFile = Import-Csv "$DesktopPath\Auploy\Users\Users.csv"
$Global:BaseFile = Import-Csv "$DesktopPath\Auploy\Settings\Host\Basefile.csv"
$Global:GPOSettings = Import-Csv "$DesktopPath\Auploy\Settings\GPO\GPOSettings.csv"
$Global:GPOStructure = Import-Csv "$DesktopPath\Auploy\Settings\GPO\GPOStructure.csv"
$Global:GroupsFile = Import-Csv "$DesktopPath\Auploy\Users\UserGroups.csv"
$Global:DriveMap = Import-Csv "$DesktopPath\Auploy\Settings\Drives\DriveMap.csv"
}

catch {Get-UsernameInput}


if ($error){

$Global:OUFile = Import-Csv "$AuployPath\Auploy\Settings\OU\OU.csv"
$Global:UserFile = Import-Csv "$AuployPath\Auploy\Users\Users.csv"
$Global:BaseFile = Import-Csv "$AuployPath\Auploy\Settings\Host\Basefile.csv"
$Global:GPOSettings = Import-Csv "$AuployPath\Auploy\Settings\GPO\GPOSettings.csv"
$Global:GPOStructure = Import-Csv "$AuployPath\Auploy\Settings\GPO\GPOStructure.csv"
$Global:GroupsFile = Import-Csv "$AuployPath\Auploy\Users\UserGroups.csv"
$Global:DriveMap = Import-Csv "$AuployPath\Auploy\Settings\Drives\DriveMap.csv"

}

$Global:TopOU = $Basefile.TopOU[0]
$Global:Password = $Basefile.Password[0]
$Global:HostIP = $Basefile.IPV4[0]
$Global:SecondaryIP = $Basefile.IPV4[1]
$Global:Hostname = $Basefile.Hostname[0]
$Global:SecHostname = $Basefile.Hostname[1]
$Global:GatewayIPObject = $Basefile.Gateway[0]
$Global:MaskObject = $Basefile.Mask[0]
$Global:NetworkID = $Basefile.NetworkID[0]
$Global:DHCPStart = $Basefile.Start[0]
$Global:DHCPEnd = $Basefile.End[0]
[int32] $Global:DHCPPercent = $Basefile.Percent[0]
$Mask = $MaskObject
$GatewayIP = $GatewayIPObject

####################################### Create VM's and Drives ##########################################

function Get-VMProperties{


      $Global:Userval = Read-Host "Server or Host? (S/H) "
      $Global:CurrentMachine = Read-Host "Location?"
      $Global:VMName = Read-Host "Enter the VM Name"
      [int32] $Global:VMCores = Read-Host "Number of Cores"
      $Continue = 1


    if ($Continue -eq 1){
  

        if ($CurrentMachine -eq "Home" -and $Userval -eq "S"){

          $Global:VMPath = "C:\Users\Owner\Desktop\VM Trials\"
          $Global:VHDPath = "C:\Users\Owner\Desktop\VM Trials\$VMname\$VMname" + ".vhdx"
          $Global:Imagepath = "C:\Users\Owner\Documents\ISO Files\Windows Server 2019 DataCenter en-US MAY 2021 {Gen2}\SRV2019.DC.ENU.MAY2021.iso"

          }

        elseif ($CurrentMachine -eq "Home" -and $Userval -eq "H"){

          $Global:VMPath = "C:\Users\Owner\Desktop\VM Trials\"
          $Global:VHDPath = "C:\Users\Owner\Desktop\VM Trials\$VMname\$VMname" + ".vhdx"
          $Global:Imagepath = "C:\Users\Owner\Documents\ISO Files\Windows.iso"

          }


        else{

          $Global:VMPath = Read-Host "Enter the VM Path"
          $Global:VHDPath = Read-Host "Enter the VHD Path with Name(.Vhdx)"
          $Global:Imagepath = Read-Host "Enter the ISO Path"

          }

          if ($Userval -eq "H" -or $Userval -eq "h"){
            Make-VMHost
            Write-Host "VM Created at Path $VMPath"
          }

          elseif ($Userval -eq "S" -or $Userval -eq "s"){
            Make-VMServer
            Write-Host "VM Created at Path $VMPath"
          }

}
}


function Make-VMServer {
    
try{
  New-VM -Name $VMName -Path $VMPath -MemoryStartupBytes 4GB -Generation 2 -Switchname "External Virtual Switch"
  New-VHD -Path "$VHDPath" -Dynamic -SizeBytes 120GB
  Add-VMDvdDrive -VMName $VMName -Path $Imagepath
  Set-VMProcessor $VMname -Count $VMCores -Reserve 10 -Maximum 75
  Get-VM "$VMName" | Add-VMHardDiskDrive -ControllerType SCSI -ControllerNumber 0 -Path $VHDPath
  $VMObject = Get-VMFirmware $VMname
  Set-BootOrder

  $NetDrives = Read-Host "Create and Attach CSV Specified Drives for Network Storage?"

  }

Catch{ Write-Host "You Might need Elevated privileges"}

if ($NetDrives -eq "Y"){
  Make-NetDrives

  }

  }


  function Make-VMHost {


  New-VM -Name "$VMName" -Path $VMPath -MemoryStartupBytes 2GB -Generation 2 -Switchname "External Virtual Switch"
  New-VHD -Path "$VHDPath" -Dynamic -SizeBytes 120GB
  Add-VMDvdDrive -VMName $VMName -Path $Imagepath
  Set-VMProcessor $VMname -Count $VMCores -Reserve 10 -Maximum 75
  Get-VM "$VMName" | Add-VMHardDiskDrive -ControllerType SCSI -ControllerNumber 0 -Path $VHDPath
  Set-BootOrder

}


function Set-BootOrder{

$VMname = $VMname
$VMObject = Get-VMFirmware $VMname
$VMBootOrder = $VMObject.BootOrder

$Network = $VMBootOrder[0]
$DVD = $VMBootOrder[1]
$VHD = $VMBootOrder[2]

Set-VMFirmware -VMName $VMname -BootOrder $DVD,$VHD,$Network

}


function Make-NetDrives{

  if ($NetDrives -eq "Y"){
    $i = 0
    foreach ($Drive in $Drivemap){
        
        $NetworkDrive = "$VMPath" + "$Drive.Groups[$i]" + ".Vhdx"
        New-VHD -Path "$NetworkDrive" -Dynamic -SizeBytes 120GB
        Get-VM "$VMName" | Add-VMHardDiskDrive -ControllerType SCSI -ControllerNumber 0 -Path $NetworkDrive
        $i++
        }
}

}


function Add-Network{



##GRAB INTERFACE INDEX
$AutoIndex = Get-NetAdapter -Name * -Physical
[int] $Intindex = $AutoIndex.Interfaceindex


##SET STATIC ADDRESS
New-NetIPAddress -InterfaceIndex $Intindex -IPAddress $HostIP -Prefixlength 24 `
-DefaultGateway $GatewayIP -AddressFamily IPv4

## SET DNS
Set-DnsClientServerAddress -InterfaceIndex $IntIndex -ServerAddresses ("$HostIP","$SecondaryIP")


}

function Disable-IpV6{
##Disable IPv6
$IPv6Check = Get-NetAdapterBinding | Where-Object ComponentID -EQ 'ms_tcpip6'
$IPv6Status = $IPv6Check.enabled


if ($IPv6Status -eq $True){

Disable-NetAdapterBinding -Name 'Ethernet' -ComponentID 'ms_tcpip6'

}

}


function Set-HostName{


Rename-Computer -NewName "$Global:Hostname"

}

function Set-DNS{

Set-DnsClientServerAddress -InterfaceIndex $IntIndex -ServerAddresses ("$HostIP","$SecondaryIP")

}


####################################### Setup Roles and Static Settings ##########################################

function Add-PrimaryADRoles {

  Install-windowsfeature -Name AD-Domain-Services -IncludeManagementTool
  Install-windowsfeature -Name DHCP -IncludeManagementTool
  Install-ADDSForest -DomainName HQ.Raudz.Com -InstallDNS -Force

}

function Add-SecondaryADRoles {

  Install-windowsfeature -Name AD-Domain-Services -IncludeManagementTool
  Install-windowsfeature -Name DHCP -IncludeManagementTool
  Install-WindowsFeature -Name DNS -IncludeManagementTools
}

function Set-DNSSecondary{
  $Stall = Read-Host "Press [Enter] When You are Ready For The DNS Zone Transfer"
  Add-DhcpServerInDC -DnsName HQ.Raudz.Com  -IPAddress 192.168.1.2
  Add-DnsServerSecondaryZone -MasterServers "$HostIP" -Name HQ.Raudz.Com -ZoneFile HQ.Raudz.Com
  Add-DnsServerSecondaryZone -MasterServers "$HostIP" -Name 1.168.192.in-addr.arpa -ZoneFile 1.168.192.in-addr.arpa
  Get-DnsServerZone
}


function Add-DHCPRole {

  Install-windowsfeature DHCP -IncludeManagementTools

}

function Set-DHCPRole {

  Add-DhcpServerInDC -DnsName HQ.Raudz.Com  -IPAddress 192.168.1.1
  Add-DhcpServerInDC -DnsName HQ.Raudz.Com  -IPAddress 192.168.1.2
  Add-DhcpServerv4Scope -Name "$Top Network" -StartRange $DHCPStart -EndRange $DHCPEnd -SubnetMask 255.255.255.0

}

function Add-DHCPFailover{

Add-DhcpServerv4Failover `
-ComputerName dc01 `
-Name "Network" `
-PartnerServer dc02 `
-ScopeId $DHCPStart,$DHCPEnd `
-LoadBalancePercent 50 `
-SharedSecret "P@ssw0rd!!" `
-MaxClientLeadTime 2:00:00 `
-AutoStateTransition $True `
-StateSwitchInterval 2:00:00

}

function Set-DNSRecords{

Remove-DnsServerResourceRecord -Zonename HQ.Raudz.Com -InputObject (Get-DNsServerResourceRecord -ZoneName "HQ.Raudz.Com" -Type 1 -Name "dc01")

Add-DnsServerResourceRecordA `
-Name "dc01" `
-ZoneName "HQ.Raudz.Com" `
-CreatePtr `
-IPv4Address 192.168.1.1 `
-TimeToLive 01:00:00 `



Add-DnsServerResourceRecordA `
-Name "dc02" `
-ZoneName "HQ.Raudz.Com" `
-CreatePtr `
-IPv4Address 192.168.1.2 `
-TimeToLive 01:00:00 `



}

<#

function Do-DNSZoneTransfer{

Add-DnsServerSecondaryZone -MasterServers $HostIP -Name "$Top.$Space.$Root" -ZoneFile "$Top.$Space.$Root"
Start-DnsServerZoneTransfer -Name "$Top.$Space.$Root" 
Get-DnsServerResourceRecord -ZoneName "$Top.$Space.$Root"

}

#>

function Set-FWPermissions{

    New-NetFirewallRule -DisplayName "Allow IPv4 Ping Inbound" -Name "Allow IPv4 Ping Inbound" -direction Inbound -IcmpType 8 -Protocol ICMPv4 -Action Allow
    New-NetFirewallRule -DisplayName "Allow IPv4 Ping Outbound" -Name "Allow IPv4 Ping Outbound" -direction Outbound -IcmpType 8 -Protocol ICMPv4 -Action Allow

}
function Add-Host{

Add-Computer -DomainName $HostDomain -Restart

}

##################################### Create the AD DS Structure ################################################

function Set-OUPath {

<#
.SYNOPSIS
Creates a Top level OU.

.DESCRIPTION
Finds the Current Path for the in place Domain Controller and uses it to create global variables for a distinguished name path. A specified Top level OU Will be created from the value set in the imported basefile.

.NOTES
General notes
#>


  $DCPath = Get-ADOrganizationalUnit -Filter 'Name -like "Domain Controllers"'
  $OUBase = $DCpath.DistinguishedName
  $OU,$Global:Top,$Global:Space,$Global:Root = $OUBase.split(",")
  New-ADOrganizationalUnit -Name $TopOU -Path "$Top,$Space,$Root" -ProtectedFromAccidentalDeletion $False


}


function Make-OUStructure {

<#
.SYNOPSIS
Author: Tyler Dorner

Creates the desired OU Structure from an Imported CSV File, supports one layer nesting.

.DESCRIPTION
Loads a Specified CSV file for a reference, then finds the Current Path for the in place Domain Controller and uses it to place new users in the specified Organizational Units. Sub OU's will be detected and added from a second column and the full OU structure will be displayed to the console.

.NOTES
Make sure the CSV file is correctly Formatted for the OU Structure before importing ---> The Headers Must be "Name,Sub,Top,Nest" | This is a function that will reside in the full script and the global paths will be re-used.
#>


  foreach ($OU in $OUFile) {

    ##Creates Single Layer Nesting

    if ($OU.Name -ne "") {


      $TopOUObject = Get-ADOrganizationalUnit -Filter 'Name -like $TopOU'
      $TopOUPath = $TopOUObject.DistinguishedName


      New-ADOrganizationalUnit -Name $OU.Name -Path "$TopOUPath" -ProtectedFromAccidentalDeletion $False

    if ($OU.Sub -ne "") {

        $Sub = $OU.Sub.split(",")

        foreach ($OUSub in $Sub) {

          $TopSubOU = $OU.Name
          $SubOUObject = Get-ADOrganizationalUnit -Filter 'Name -like $TopSubOU'
          $SubOUPath = $SubOUObject.DistinguishedName
          New-ADOrganizationalUnit -Name $OUSub -Path "$SubOUPath" -ProtectedFromAccidentalDeletion $False

        }




      }
    }

    ##Creates Multi-layer Nesting

    if ($OU.Top -ne "") {

      ##Find Nest Path
      $NestOUTop = $OU.Top
      $NestOUObject = Get-ADOrganizationalUnit -Filter 'Name -like $NestOUTop'
      $NestOUPath = $NestOUObject.DistinguishedName

      ## Split Nest
      $NestOUName = $OU.Nest.split(",")

      foreach ($NestOU in $NestOUName) {

        New-ADOrganizationalUnit -Name $NestOU -Path "$NestOUPath" -ProtectedFromAccidentalDeletion $False

      }

    }


  }

  Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Format-Table Name,DistinguishedName -A


}


function Add-OUUsers {

<#
.SYNOPSIS
Imports Users From a CSV File and Adds Them Into A Specified OU Structure.

.DESCRIPTION
Searches for a matching OU that contains the users Subdepartment. Users will be created and referenced by their EmployeeID and must login with that as their username. 

.NOTES
General notes
#>


  #Import-Module activedirectory

  foreach ($User in $Userfile) {

    $Username = $User. "First Name"[0] + "." + $User. "Last Name"
    $OU = $User.Subdepartment
    $Firstname = $User. "First Name"
    $Lastname = $User. "Last Name"
    $Display = "$Firstname" + " " + "$Lastname"
    $Site = $User.Site
    $Title = $User.Title
    $Department = $User.Department
    $EmployeeID = $User. "Employee ID"
    $OUObject = Get-ADOrganizationalUnit -Filter 'Name -like $OU'
    $OUpath = $OUObject.DistinguishedName





    if (Get-ADUser -F { SamAccountName -EQ $EmployeeID }) {
      Write-Warning "A user account with username $Username already exist in Active Directory."
    }

    else {

      New-ADUser -SamAccountName "$EmployeeID" `
         -UserPrincipalName "$EmployeeID@$TopOU.Com" `
         -Name "$Display" `
         -GivenName "$Firstname" `
         -Surname "$Lastname" `
         -Enabled $True `
         -DisplayName "$Display" `
         -Path $OUpath `
         -Company "$Site" `
         -Title $Title `
         -Description $Title `
         -Department $Department `
         -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) -ChangePasswordAtLogon $True
      Write-Host "$Username Created"

    }


  }


}


function Make-GPOStructure {


<#
.SYNOPSIS
Creates a GPO in the Assigned OU with Values From GPOSettings.Csv

.DESCRIPTION
Long description

.EXAMPLE
An example

.NOTES
General notes
#>


  foreach ($GPO in $GPOStructure) {

    $GPOName = $GPO.Name
    $GPOLinks = $GPO.Link.split(",")


    new-gpo -Name "$GPOName"

    foreach ($Link in $GPOLinks) {

      $GPOPathObject = Get-ADOrganizationalUnit -Filter 'Name -like $Link'
      $GPOPath = $GPOPathObject.DistinguishedName
      new-gplink -Name "$GPOName" -target "$GPOPath"

    }




  }
}


function Add-GPOValues {




  foreach ($Setting in $GPOSettings) {

    $GPOPolicy = $Setting.Policy
    $GPOValue = $Setting.Value
    $GPOType = $Setting.Type
    $GPOName = $Setting.Name
    $GPOKey = $Setting.Key





    if ($GPOType -eq "DWord") {

      [int]$DWord = $GPOValue

      Set-GPRegistryValue `
         -Name $GPOPolicy `
         -Key $GPOKey `
         -ValueName $GPOName `
         -Value $DWord `
         -Type $GPOType `



    }

    if ($GPOType -eq "String") {


      Set-GPRegistryValue `
         -Name $GPOPolicy `
         -Key $GPOKey `
         -ValueName $GPOName `
         -Value $GPOValue `
         -Type $GPOType `

    }


  }

}


function Add-ADGroup {



  foreach ($Group in $GroupsFile) {


    $GroupOUName = $Group.Path
    $GroupDesc = $Group.Description
    $GroupPathObject = Get-ADOrganizationalUnit -Filter 'Name -like $GroupOUName'
    $GroupPath = $GroupPathObject.DistinguishedName

    New-ADGroup `
       -Name $GroupOUName `
       -SamAccountName $GroupOUName `
       -GroupCategory Security `
       -GroupScope Global `
       -DisplayName $GroupOUName `
       -Path $GroupPath `
       -Description $GroupDesc


    $GroupMembers = Get-ADUser -Filter * -SearchBase $GroupPathObject



    foreach ($Member in $GroupMembers) {

      $SamAccount = $Member.SamAccountName
      Add-ADGroupMember -Identity $GroupOUName -Members $SamAccount


    }

  }
}

function Set-PasswordPolicy {

  Get-ADDefaultDomainPasswordPolicy -Current LoggedOnUser | `
     Set-ADDefaultDomainPasswordPolicy `
     -ComplexityEnabled $true `
     -MinPasswordLength 10 `
     -MaxPasswordAge "60.00:00:00" `
     -PasswordHistoryCount 3 `
     -LockoutDuration "0.00:00:05" `
     -LockoutObservationWindow "0.00:00:05" `
     -LockoutThreshold 3

}


function Set-ComputerPath{


## Remove Hard Code Later
redircmp “OU=Computers,OU=Raudz,DC=HQ,DC=Raudz,DC=Com”

}

######################################## Deployment Menu Functions ############################################

function Main-Selection{



if ($Choice -eq "1") {

    Get-VMProperties
    Title-Screen

}

elseif ($Choice -eq "2") {

    $Global:HostIP = $Basefile.IPV4[0]
    $Global:SecondaryIP = $Basefile.IPV4[1]
    $Global:Hostname = $Basefile.Hostname[0]
    Add-Network
    Set-Hostname
    Disable-IPv6
    Restart-Computer
    Title-Screen


}
elseif ($Choice -eq "3") {
    $Global:HostIP = $Basefile.IPV4[1]
    $Global:SecondaryIP = $Basefile.IPV4[0]
    $Global:Hostname = $Basefile.Hostname[1]
    Add-Network
    Set-Hostname
    Disable-IPv6
    Restart-Computer
    Title-Screen
    
}


elseif ($Choice -eq "4") {
    Add-PrimaryADRoles
    Set-FWPermissions
    Set-DHCPRole
    


}


elseif ($Choice -eq "5") {
    
    Add-SecondaryADRoles
    Set-FWPermissions
    Install-ADDSDomainController -Domainname "HQ.Raudz.Com" -Credential (Get-Credential "HQ\Administrator")

}

elseif ($Choice -eq "6") {
      Set-DNSRecords
      Main-Selection
}


elseif ($Choice -eq "7") {
      Set-DNSSecondary
      Main-Selection
}


elseif ($Choice -eq "8") {

    Set-OUPath
    Make-OUStructure
    Make-GPOStructure
    Add-GPOValues
    Add-OUUsers
    Add-ADGroup
    Set-PasswordPolicy
    Set-ComputerPath
    Set-DHCPRole
    Main-Selection

}

elseif ($Choice -eq "9") {
    Add-DHCPFailover
    Main-Selection
}

elseif ($Choice -eq "10") {
 set-executionpolicy remotesigned -Force
 $Global:Hostname = Read-Host "Enter The New Hostname"
 $Global:HostDomain = Read-Host "Enter Domain Name"
 Set-Hostname
 Set-DNS
 Add-Host
 Main-Selection

}

elseif ($Choice -eq "11") {
    Standalone-Tools
}

elseif ($Choice -eq "12") {
    Exit
}

}



######################################## Standalone Menu Functions ############################################



function Standalone-Selection{

    if ($Choice -eq "1"){
        set-executionpolicy remotesigned -Force
        Standalone-Tools


    }

    elseif ($Choice -eq "2"){
    $Global:HostIP = Read-Host "Enter IPv4 Address"
    $Global:SecondaryIP = Read-Host "Enter Secondary DNS"
    Standalone-Tools

    }

    elseif ($Choice -eq "3"){
        $Global:Hostname = Read-Host "Enter The New Hostname"
        Set-Hostname
        Restart-Computer
        Standalone-Tools
        

    }

    elseif ($Choice -eq "4"){
    $Global:HostDomain = Read-Host "Enter Domain Name"
    Add-Host
    Standalone-Tools

    }

    elseif ($Choice -eq "5"){
    Add-SecondaryADRoles
    Standalone-Tools
    }

    elseif ($Choice -eq "6"){
    Set-FWPermissions
    Standalone-Tools

    }

    elseif ($Choice -eq "7"){
    Set-DNSRecords
    Standalone-Tools

    }

    elseif ($Choice -eq "8"){
       Set-DNSRecords
       Standalone-Tools
    }

    elseif ($Choice -eq "9"){
        Add-DHCPFailover
        Standalone-Tools
    }

    elseif ($Choice -eq "10"){
    Standalone-Tools

    }
    elseif ($Choice -eq "11"){
    Standalone-Tools

    }

    elseif ($Choice -eq "12"){
    Standalone-Tools

    }

    elseif ($Choice -eq "13"){
    Standalone-Tools

    }

    elseif ($Choice -eq "Back" -or $Choice -eq "back"){
            Title-Screen

        }

}

function Title-Screen { Write-Host `
     "






              ▄▄▄       █    ██  ██▓███   ██▓     ▒█████ ▓██   ██▓
             ▒████▄     ██  ▓██▒▓██░  ██▒▓██▒    ▒██▒  ██▒▒██  ██▒
             ▒██  ▀█▄  ▓██  ▒██░▓██░ ██▓▒▒██░    ▒██░  ██▒ ▒██ ██░
             ░██▄▄▄▄██ ▓▓█  ░██░▒██▄█▓▒ ▒▒██░    ▒██   ██░ ░ ▐██▓░
              ▓█   ▓██▒▒▒█████▓ ▒██▒ ░  ░░██████▒░ ████▓▒░ ░ ██▒▓░
              ▒▒   ▓▒█░░▒▓▒ ▒ ▒ ▒▓▒░ ░  ░░ ▒░▓  ░░ ▒░▒░▒░   ██▒▒▒ 
               ▒   ▒▒ ░░░▒░ ░ ░ ░▒ ░     ░ ░ ▒  ░  ░ ▒ ▒░ ▓██ ░▒░ 
               ░   ▒    ░░░ ░ ░ ░░         ░ ░   ░ ░ ░ ▒  ▒ ▒ ░░  
                      ░  ░   ░                  ░  ░    ░ ░  ░ ░     
                                                             ░ ░     

            Author: Vesec
            V.0.2

            ---------------Windows Server Tools-------------------

            Tools:

            1.  Create VM Host or Server
            2.  Set Static Default Settings (DC01)
            3.  Set Static Default Settings (DC02)
            4.  Setup Roles Primary Domain Controller (DC01)
            5.  Setup Roles Secondary Domain Controller (DC02)
            6.  Setup Primary DNS Records (DC01)
            7.  Start DNS Zone Transfer (DC02)
            8.  Build AD DS Structure (DC01)
            9.  Create DHCP Failover (DC01) -Buggy
            10. Setup Host For a Domain (PC)
            11. Standalone Setup Tools (Incomplete)
            12. Exit


"

Selection
Main-Selection
}



function Standalone-Tools{ "

            ---------------Standalone Tools----------------------

            Type Back to Return to Automatic Deployment Tools

            Tools:

            1.  Enable Scripts on Host
            2.  Set DNS
            3.  Set Hostname
            4.  Add Computer to a Domain
            6.  Install AD DS
            5.  Add Secondary DNS Records
            7.  Set DNS Records
            8.  Install DHCP
            9.  Configure Primary DHCP
            10. Configure Primary DNS
            11. Configure Secondary DHCP
            12. Configure Secondary DNS
            13. Create and Mount VHD
            14. Change VM Boot Order
            15. Activate a Drive

"
Selection
Standalone-Selection

}


function Selection {
  $Global:Choice = Read-Host "Selection "

}


######## LOAD MENU ##########


Title-Screen
