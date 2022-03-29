<#

Auploy Author: Tyler Dorner
Version: V.0.5
Date: March 24th 2022
Comments:

#>

$Scriptpath = $MyInvocation.MyCommand.Path
[int] $NameLength = ($MyInvocation.MyCommand.Name).length + 8
$Global:AuployPath = $Scriptpath -replace ".{$NameLength}$"



function Get-AuployPath{
<#
.SYNOPSIS
Detects The Path To Auploy From Expected Location, Prompts User To input Path If Unable To Find Settings.

.DESCRIPTION
Long description

#>

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

Could Not find Settings

Expected Settings Directory $Auploypath

Enter Enter Path To Folder Containing Auploy"

}


try{

  $Global:OUFile = Import-Csv "$AuployPath\Settings\OU\OUStructure.csv"
  $Global:UserFile = Import-Csv "$AuployPath\Users\Users.csv"
  $Global:BaseFile = Import-Csv "$AuployPath\Settings\Host\Basefile.csv"
  $Global:GPOSettings = Import-Csv "$AuployPath\Settings\GPO\GPOKeyPolicies.csv"
  $Global:GPOStructure = Import-Csv "$AuployPath\Settings\GPO\GPOStructure.csv"
  $Global:GPOBackups = Import-Csv "$AuployPath\Settings\GPO\GPOBackups.csv"
  $Global:GroupsFile = Import-Csv "$AuployPath\Users\UserGroups.csv"
  $Global:DriveMap = Import-Csv "$AuployPath\Settings\Drives\DriveMap.csv"
  $Global:NetworkConfig = Import-CSV "$Auploypath\Settings\Host\NetworkSettings.csv"
  }

catch {

    try{
        
      $DesktopPath = [Environment]::GetFolderPath("Desktop")
      $AuployPath = "$DesktopPath\Auploy"
      $Global:OUFile = Import-Csv "$AuployPath\Settings\OU\OUStructure.csv"
      $Global:UserFile = Import-Csv "$AuployPath\Users\Users.csv"
      $Global:BaseFile = Import-Csv "$AuployPath\Settings\Host\Basefile.csv"
      $Global:GPOSettings = Import-Csv "$AuployPath\Settings\GPO\GPOKeyPolicies.csv"
      $Global:GPOStructure = Import-Csv "$AuployPath\Settings\GPO\GPOStructure.csv"
      $Global:GPOBackups = Import-Csv "$AuployPath\Settings\GPO\GPOBackups.csv"
      $Global:GroupsFile = Import-Csv "$AuployPath\Users\UserGroups.csv"
      $Global:DriveMap = Import-Csv "$AuployPath\Settings\Drives\DriveMap.csv"
      $Global:NetworkConfig = Import-CSV "$Auploypath\Settings\Host\NetworkSettings.csv"

    }
    catch{Get-AuployPath}

}

<#
$Global:HostIP = $Basefile.IPV4[0]
$Global:SecondaryIP = $Basefile.IPV4[1]
$Global:Hostname = $Basefile.Hostname[0]
$Global:SecHostname = $Basefile.Hostname[1]
$GLobal:Subnet = $Basefile.Subnet[0]
$Global:GatewayIP = $Basefile.Gateway[0]
$Global:Mask = $Basefile.Mask[0]
$Global:DHCPStart = $Basefile.DHCPStart[0]
$Global:DHCPEnd = $Basefile.DHCPEnd[0]
$Global:DNSReverse = $Basefile.NetworkID[0]
$Global:VPNStart = $Basefile.VPNStart[0]
$Global:VPNEnd = $Basefile.VPNEnd[0]
[int32] $Global:DHCPPercent = $Basefile.Percent[0]
$Global:Roles = $Basefile.Roles[0]
$Global:ServerRole = $Basefile.Server[0]

#>

$Global:TopOU = $Basefile.TopOU[0]
$Global:Password = $Basefile.Password[0]
$Global:VMHDDSize = 0 + 120GB
$Global:Forest = $Basefile.Forest[0]
$Global:VMSwitch = $Basefile.Switch[0]


####################################### Create VM's #######################################################

function Get-VMProperties{
<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.EXAMPLE
An example

.NOTES
General notes
#>


      $Global:Userval = Read-Host "Server or Host? (S/H) "
      $Global:CurrentMachine = Read-Host "Location?"
      $Global:VMName = Read-Host "Enter the VM Name"
      [int32] $Global:VMCores = Read-Host "Number of Cores"
      $Continue = 1


    if ($Continue -eq 1){
  

        if ($CurrentMachine -eq "Home" -and $Userval -eq "S"){

          $Global:VMPath = "C:\Users\Owner\Desktop\VM Trials\"
          $Global:VHDPath = "C:\Users\Owner\Desktop\VM Trials\$VMname\$VMname" + ".vhdx"
          $Global:Imagepath = "C:\Users\Owner\Documents\ISO Files\Windows Server 2022.iso"

          }

        elseif ($CurrentMachine -eq "Home" -and $Userval -eq "H"){

          $Global:VMPath = "C:\Users\Owner\Desktop\VM Trials\"
          $Global:VHDPath = "C:\Users\Owner\Desktop\VM Trials\$VMname\$VMname" + ".vhdx"
          $Global:Imagepath = "C:\Users\Owner\Documents\ISO Files\Windows.iso"

          }
        elseif ($CurrentMachine -eq "School" -and $Userval -eq "S"){

          $Global:VMPath = "$AuployPath\VM's\"
          $Global:VHDPath = "$AuployPath\$VMname\$VMname" + ".vhdx"
          $Global:Imagepath = "C:\ISO's\Server 2022\20348.169.210806-2348.fe_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso
          "

          }
        elseif ($CurrentMachine -eq "School" -and $Userval -eq "H"){

          $Global:VMPath = "$AuployPath\VM's\"
          $Global:VHDPath = "$AuployPath\$VMname\$VMname" + ".vhdx"
          $Global:Imagepath = "C:\ISO's\Win 10 Ent\Windows 10 1903.iso"
  
            }

        else{

          $Global:VMPath = Read-Host "Enter the VM Path"
          $Global:VHDPath = Read-Host "Enter the VHD Path with Name(.Vhdx)"
          $Global:Imagepath = Read-Host "Enter the ISO Path"

          }

          if ($Userval -eq "H" -or $Userval -eq "h"){
            $Global:VMRam = 0 + 2GB
          }

          elseif ($Userval -eq "S" -or $Userval -eq "s"){
            $Global:VMRam = 0 + 4GB
          }

          else{

            $Global:VMRam = 0 + 2GB
          }

          Add-UserVM

          if ($VMCreated -ne 0){
          Write-Host "
          
          
          VM Created at Path $VMPath"
        }


}
}

function Add-UserVM {
<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.EXAMPLE
An example

.NOTES
General notes
#>

  New-VM -Name $VMName -Path $VMPath -MemoryStartupBytes $VMRam -Generation 2 -Switchname "External Virtual Switch" -ErrorAction SilentlyContinue
  New-VHD -Path "$VHDPath" -Dynamic -SizeBytes $VMHDDSize -ErrorAction SilentlyContinue
  Add-VMDvdDrive -VMName $VMName -Path $Imagepath -ErrorAction SilentlyContinue
  Set-VMProcessor $VMname -Count $VMCores -Reserve 10 -Maximum 75 -ErrorAction SilentlyContinue

try{
  Get-VM "$VMName" -ErrorAction SilentlyContinue | Add-VMHardDiskDrive -ControllerType SCSI -ControllerNumber 0 -Path $VHDPath 
  Set-BootOrder

  $NetDrives = Read-Host "Create and Attach CSV Specified Drives for Network Storage?"

  }

catch{ Write-Warning "
  

        Whoops, Looks like You Might need Elevated privileges" -WarningAction Inquire
        $Global:VMCreated = 0
            
}

if ($NetDrives -eq "Y"){
  Add-NetDrives

  }
}

function Set-BootOrder{
<#
.SYNOPSIS
Sets the boot order for ISO attached VM's.

.DESCRIPTION
Long description

.EXAMPLE
An example

.NOTES
General notes
#>

$VMObject = Get-VMFirmware $VMname -ErrorAction SilentlyContinue
$VMBootOrder = $VMObject.BootOrder

$Network = $VMBootOrder[0]
$DVD = $VMBootOrder[1]
$VHD = $VMBootOrder[2]

Set-VMFirmware -VMName $VMname -BootOrder $DVD,$VHD,$Network

}


function Add-NetDrives{
<#
.SYNOPSIS
Uses the DriveMap.Csv To Create the Specified Network Drives. 

.DESCRIPTION
Long description

.EXAMPLE
An example

.NOTES
General notes
#>

  if ($NetDrives -eq "Y"){
  
    foreach ($Drive in $Drivemap){
        
        $NetworkDrive = "$VMPath" + $Drive.Name + $Vmname + ".Vhdx"
        New-VHD -Path "$NetworkDrive" -Dynamic -SizeBytes $VMHDDSize
        Get-VM "$VMName" | Add-VMHardDiskDrive -ControllerType SCSI -ControllerNumber 0 -Path $NetworkDrive

        }
}

}

function Add-NetDrivesPath{
  <#
  .SYNOPSIS
    Creates a Drive Share for CSV Specified User Groups, and Employs Exclusions.
  
  .DESCRIPTION
  Long description
  
  .EXAMPLE
  An example
  
  .NOTES
  General notes
  #>

    foreach ($Drive in $Drivemap){

        $Letter = $Drive.Letter
        $DriveName = $Drive.Name

        $Groups = ($Drive.Groups).Split(",")
        $GroupArray = @();$GroupArray += $Groups
        
        $Exclusions = ($Drive.Exclude).split(",")
        $ExclusionArray = @();$ExclusionArray += $Exclusions
        
        if ($Drive.Exclude -eq ""){
        New-smbshare -Name "$DriveName" -Path "${Letter}:\" -ChangeAccess $GroupArray
        }
        elseif ($Drive.Exclude -ne ""){
        New-smbshare -Name "$DriveName" -Path "${Letter}:\" -ChangeAccess $GroupArray -NoAccess $ExclusionArray
        }
        
    
    }
  }

  function Add-DriveProperties{
    diskpart.exe /s "$AuployPath\Settings\Drives\ActivateDrives.txt"
  }


####################################### Setup Roles and Static Settings ##########################################

function Set-HostName{

  Rename-Computer -NewName "$Global:Hostname"
  
  }
  
  function Set-HostDNS{

  $AutoIndex = Get-NetAdapter -Name * -Physical
  [int] $Intindex = $AutoIndex.Interfaceindex

  Set-DnsClientServerAddress -InterfaceIndex $IntIndex -ServerAddresses ("192.168.1.1","192.168.1.2","192.168.2.1","192.168.2.2")
  
  }

  function Add-RRASNetSettings{

    $AutoIndex = Get-NetAdapter -Name * -Physical
    [int] $LANIntIndex = $AutoIndex.InterfaceIndex[0]
    [int] $WANIntIndex = $AutoIndex.InterfaceIndex[1]
    $LANName = $AutoIndex.Name[0]
    $WANNAme = $AutoIndex.Name[1]
    
    
    foreach($Line in $NetworkConfig){
    
        $RRASIP = $Line.IPAddress
        $RRASMask = $Line.Mask
        $RRASGatewayIP = $Line.Gateway
    
        if($Line.NIC -eq "LAN" -and $Line.Hostname -eq $env:COMPUTERNAME){
    
            New-NetIPAddress -InterfaceIndex $LANIntIndex -IPAddress $RRASIP -Prefixlength $RRASMask `
            -AddressFamily IPv4
    
            Rename-NetAdapter -Name $LANName -NewName "LAN"
            
        }
    
        if($Line.NIC -eq "WAN" -and $Line.Hostname -eq $env:COMPUTERNAME){
    
            New-NetIPAddress -InterfaceIndex $WANIntIndex -IPAddress $RRASIP -Prefixlength $RRASMask `
            -DefaultGateway "$RRASGatewayIP" -AddressFamily IPv4
    
            Rename-NetAdapter -Name $WANName -NewName "WAN"
            
        }
    }
    
    }

    function Add-CalgaryRRASConnection{
      install-Remoteaccess -Computername "RRAS-Calgary" -vpntype VPNS2S -IPAddressRange "192.168.1.50","192.168.1.99" -Legacy
      Add-VPnS2SInterface -Name "RRAS-Kelowna" -Protocol IKEv2 -Destination 10.10.1.1 -AuthenticationMethod PSKonly -IPV4Subnet 191.168.1.0/24:1 -SharedSecret "P@ssw0rd!!"
      Set-VpnServerIPsecConfiguration -CustomPolicy -EncryptionMethod AES256 -AuthenticationTransformConstants SHA196 -CipherTransformConstants AES256 -IntegrityCheckMethod SHA1
      }

    function Add-KelownaRRASConnection{
      install-Remoteaccess -Computername "RRAS-Kelowna" -vpntype VPNS2S -IPAddressRange "192.168.2.50","192.168.2.99" -Legacy
      Add-VPnS2SInterface -Name "RRAS-Calgary" -Protocol IKEv2 -Destination 10.10.1.5 -AuthenticationMethod PSKonly -IPV4Subnet 191.168.2.0/24:1 -SharedSecret "P@ssw0rd!!"
      Set-VpnServerIPsecConfiguration -CustomPolicy -EncryptionMethod AES256 -AuthenticationTransformConstants SHA196 -CipherTransformConstants AES256 -IntegrityCheckMethod SHA1
      
      }

  function Disable-IpV6{
    <#
    .SYNOPSIS
    Short description
    
    .DESCRIPTION
    Long description
    
    .EXAMPLE
    An example
    
    .NOTES
    General notes
    #>
  
  
  $IPv6Check = Get-NetAdapterBinding | Where-Object ComponentID -EQ 'ms_tcpip6'
  $IPv6Status = $IPv6Check.enabled
  
  
  if ($IPv6Status -eq $True){
  
  Disable-NetAdapterBinding -Name 'Ethernet' -ComponentID 'ms_tcpip6'
  
  }
  
  }

  function Add-NetworkSettings{
    <#
    .SYNOPSIS
    Short description
    
    .DESCRIPTION
    Long description
    
    .EXAMPLE
    An example
    
    .NOTES
    General notes
    #>
    
    
    ##GRAB INTERFACE INDEX
    $AutoIndex = Get-NetAdapter -Name * -Physical
    [int] $Intindex = $AutoIndex.Interfaceindex
    
  
    ##SET STATIC ADDRESS
    New-NetIPAddress -InterfaceIndex $Intindex -IPAddress $HostIP -Prefixlength $Mask `
    -DefaultGateway $GatewayIP -AddressFamily IPv4
    
    ## SET DNS
    #Set-DnsClientServerAddress -InterfaceIndex $IntIndex -ServerAddresses ("$HostIP","$SecondaryIP","$OffsiteHostIP","$OffsiteSecondaryIP")
    }

function Add-PrimaryDCRoles {

  Install-windowsfeature -Name AD-Domain-Services -IncludeManagementTool
  Install-windowsfeature -Name DHCP -IncludeManagementTool
  Install-WindowsFeature -Name FS-DFS-Namespace,FS-DFS-Replication,FS-SMB1 –IncludeManagementTools

  if($env:COMPUTERNAME -eq "DC01-Kelowna"){
  Install-ADDSForest -DomainName "$Forest" -InstallDNS -Force -DomainNetBiosName "Raudz"
}

}

function Add-SecondaryDCRoles {


  Install-windowsfeature -Name AD-Domain-Services -IncludeManagementTool
  Install-windowsfeature -Name DHCP -IncludeManagementTool
  Install-WindowsFeature -Name DNS -IncludeManagementTools
  Install-WindowsFeature -Name FS-DFS-Namespace,FS-DFS-Replication,FS-SMB1 –IncludeManagementTools
}

function Set-HostDNSSecondary{

  $Stall = Read-Host "Press [Enter] When You are Ready For The DNS Zone Transfer"
  Add-DnsServerSecondaryZone -MasterServers "$HostIP" -Name "$Forest" -ZoneFile "$Forest"
  Add-DnsServerSecondaryZone -MasterServers "$HostIP" -Name $DNSReverse -ZoneFile $DNSReverse ##Needs the Variable supplied from CSV
  Get-DnsServerZone
}

function Set-PrimaryDHCPRole {

  Add-DhcpServerInDC -DnsName "$Forest" -IPAddress $HostIP
  Add-DhcpServerv4Scope -Name "$TopOU Network" -StartRange $DHCPStart -EndRange $DHCPEnd -SubnetMask $Subnet -State Active -LeaseDuration 4.00:00:00
  }



function Add-DHCPFailover{

Add-DhcpServerInDC -DnsName "$Forest" -IPAddress $SecondaryIP


Add-DhcpServerv4Failover `
-ComputerName "$SecHostname.$Forest" `
-Name "$TopOU Network" `
-PartnerServer "$Hostname.$Forest" `
-ScopeId $ScopeID `
-LoadBalancePercent 50 `
-MaxClientLeadTime 2:00:00 `
-AutoStateTransition $True `
-StateSwitchInterval 2:00:00

}

function Set-HostDNSRecords{
<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.EXAMPLE
An example

.NOTES
General notes
#>


Add-DnsServerPrimaryZone -NetworkID "$NetworkID/$Mask" -ReplicationScope "Forest" -ErrorAction SilentlyContinue


Remove-DnsServerResourceRecord -Zonename "$Forest" -InputObject (Get-DNsServerResourceRecord -ZoneName "$Forest" -Type 1 -Name "$Hostname") -ErrorAction SilentlyContinue

try{
Add-DnsServerResourceRecordA `
-Name "$Hostname" `
-ZoneName "$Forest" `
-CreatePtr `
-IPv4Address $HostIP `
-TimeToLive 01:00:00 ` -ErrorAction SilentlyContinue



Add-DnsServerResourceRecordA `
-Name "$SecHostname" `
-ZoneName "$Forest" `
-CreatePtr `
-IPv4Address $SecondaryIP `
-TimeToLive 01:00:00 ` -ErrorAction SilentlyContinue
}

catch{
  Write-Warning "An A Record May Already Exist, Or The Secondary Domain Controller Is not Reachable."
}



}

function Add-PTRRecords{

  $ReverseZone = Get-DnsServerZone | Where-Object {$_.Zonename -like '*192.in-addr.arpa*'}
  $ReverseNameKel, $ReverseNameCal = $ReverseZone.Zonename

  $DomainList =  Get-ADDomainController -filter "*"
  $Hostname = $DomainList.Hostname
  $IPAddress = $DomainList.Ipv4Address
  $Forest = $DomainList.Forest
  $IPsub = $IPAddress.Substring(8,3)
  $IPPrefix = $IPAddress.Substring(0,7)


foreach ($IP in $IPSub){
  $ReverseName, $PTR = $IP.Split(".")

  Add-DnsServerResourceRecordPtr `
  -Name "$PTR" `
  -ZoneName "$ReverseName.168.192.in-addr.arpa" `
  -AllowUpdateAny `
  -TimeToLive 01:00:00 `
  -AgeRecord `
  -PtrDomainName "$Forest"
  
  }

}

function Set-FWPermissions{

  try{
    New-NetFirewallRule -DisplayName "Allow IPv4 Ping Inbound" -Name "Allow IPv4 Ping Inbound" -direction Inbound -IcmpType 8 -Protocol ICMPv4 -Action Allow
    New-NetFirewallRule -DisplayName "Allow IPv4 Ping Outbound" -Name "Allow IPv4 Ping Outbound" -direction Outbound -IcmpType 8 -Protocol ICMPv4 -Action Allow
  }

  catch{ Write-Warning "Firewall Rule Already Exists"}
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

}

function Add-TopOU{

  New-ADOrganizationalUnit -Name $TopOU -Path "$Top,$Space,$Root" -ProtectedFromAccidentalDeletion $False


}


function Add-OUStructure {

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

function Add-NetworkFiles{
  Copy-Item -Path "$AuployPath\Settings\GPO\Scripts\Create-SMBMapping.ps1" -Destination "\\dc01-kelowna\SYSVOL\Int.Raudz.Com\scripts"
  Copy-Item -Path "$AuployPath\Settings\GPO\Scripts\Remove-SMBMapping.ps1" -Destination "\\dc01-kelowna\SYSVOL\Int.Raudz.Com\scripts"
  Copy-Item -Path "$AuployPath\Settings\GPO\Wallpaper" -Destination "\\dc01-kelowna\SYSVOL\Int.Raudz.Com\Wallpaper" -Recurse
}

function Add-DFSRoot{

  New-Item -Path "C:\DFSRoots\Shares" -ItemType Directory  -Force | Out-Null
  New-SmbShare -Name ShareAccess -path 'C:\DFSRoots\Shares' -ChangeAccess "Domain Users" -FullAccess "Domain Admins"
  New-DfsnRoot -TargetPath "\\DC01-KELOWNA\ShareAccess" -Type DomainV2 -Path "\\Int.Raudz.Com\ShareAccess" -GrantAdminAccounts "GrantAdmin" -EnableRootScalability $True
  }
  
  
  
  function Add-DFSFolders{
  
  $DriveArray = "Finance", "Internal", "IT Resources", "Marketing", "HR"
  
      foreach($Drive in $DriveArray){

          New-DfsReplicationGroup -GroupName "$Drive Volume" | `
          New-DfsReplicatedFolder -FolderName "$Drive" | `
          Add-DfsrMember -ComputerName "DC01-Kelowna","DC02-Kelowna" | `
          Format-Table dnsname,groupname -auto -wrap
      
          if ($Drive -eq "Finance"){
              $Letter = 'F:\'
              }
          elseif ($Drive -eq "Internal"){
              $Letter = 'I:\'
              }
          elseif ($Drive -eq "IT Resources"){
              $Letter = 'Z:\'
              }
          elseif ($Drive -eq "Marketing"){
              $Letter = 'M:\'
              }
          elseif ($Drive -eq "HR"){
              $Letter = 'H:\'
              }
          
      Add-DfsrConnection -GroupName "$Drive Volume" -SourceComputerName "DC01-Kelowna" `
      -DestinationComputerName "DC02-Kelowna" | Format-Table *name -wrap -auto
      
      Set-DfsrMembership -GroupName "$Drive Volume" -FolderName "$Drive" -ContentPath "$Letter" `
      -ComputerName "DC01-Kelowna" -PrimaryMember $True -StagingPathQuotaInMB 16384 -Force | `
      Format-Table *name,*path,primary* -auto -wrap
      
      Set-DfsrMembership -GroupName "$Drive Volume" -FolderName "$Drive" -ContentPath "$Letter" `
      -ComputerName "DC02-Kelowna" -StagingPathQuotaInMB 16384 -Force | `
      Format-Table *name,*path,primary* -autosize -wrap
      
      New-DfsnFolder `
      -Path "\\Raudz\ShareAccess\$Drive" `
      -TargetPath "\\DC01-KELOWNA\$Drive" `
      -EnableTargetFailback $True
  
  }
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


  ## Iterate Through CSV
  foreach ($User in $Userfile) {

    ## Grab and Assign CSV Info
    $Username = $User. "First Name"[0] + "." + $User. "Last Name"
    $OU = $User.Subdepartment
    $Firstname = $User. "First Name"
    $Lastname = $User. "Last Name"
    $Display = "$Firstname" + " " + "$Lastname"
    $Site = $User.Site
    $Title = $User.Title
    $Department = $User.Department
    $EmployeeID = $User."Employee ID"
    $OUObject = Get-ADOrganizationalUnit -Filter 'Name -like $OU'
    $OUpath = $OUObject.DistinguishedName

    ## User Check
    if (Get-ADUser -F { SamAccountName -eq $EmployeeID }) {
      Write-Warning "A user account with username $Username already exist in Active Directory."
    }

    else {

      ## Add User
      New-ADUser -SamAccountName "$EmployeeID" `
         -UserPrincipalName "$Firstname.$Lastname@$TopOU.com" `
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


function Add-GPOStructure {

<#
.SYNOPSIS
Creates a GPO in the Assigned OU with Values From GPOSettings.Csv

.DESCRIPTION


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
<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.EXAMPLE
An example

.NOTES
General notes
#>



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

function Import-GPOBackup{

  <#
  .SYNOPSIS
  Imports a Previously used GPO from a Specified path.
  
  .DESCRIPTION
  Imports a GPO from its ID and the detected path that the Backups are stored. 
  The Target Name will match a pre-existing gpo to change its inherent properties.
  
  .EXAMPLE
  An example
  
  .NOTES
  General notes
  #>

  
      foreach ($GPO in $GPOBackups){
      $GPOID = $GPO.ID
      $GPOTarget = $GPO.Target
      import-gpo `
      -BackupId "$GPOID" `
      -TargetName "$GPOTarget" `
      -path "$AuployPath\Settings\GPO\Backups" `
      -CreateIfNeeded
    }
  
      
  }

function Add-ADGroup {
<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.EXAMPLE
An example

.NOTES
General notes
#>

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

function Add-DriveProperties{
  diskpart.exe /s "$AuployPath\Settings\Drives\ActivateDrives.txt"
}

function Set-ComputerPath{

redircmp “OU=Computers,OU=$TopOU,$Top,$Space,$Root”

}

######################################## Title Menu Functions ############################################

function Get-TitleFunctions{

  if ($UserChoice -eq "1") {

      Get-VMProperties
      Get-TitleScreen

  }

  if ($UserChoice -eq "2") {

      Get-DeploymentMenu

  }

  elseif ($UserChoice -eq "3") {
      set-executionpolicy remotesigned -Force
      $Global:Hostname = Read-Host "Enter The New Hostname"
      Set-Hostname
      Set-HostDNS
      Restart-Computer
      Get-TitleScreen

  }

  elseif ($UserChoice -eq "4") {
      $Global:HostDomain = Read-Host "Enter Domain Name (Default $Forest)"

      if ($HostDomain -eq ""){
        $Global:HostDomain = "$Forest"
      }
      Add-Host
      Get-TitleScreen
  }

  elseif ($UserChoice -eq "5") {
      Get-ToolsMenu
  }
  elseif ($UserChoice -eq "6") {
      Exit
  }

}



######################################## Standalone Menu Functions ############################################



function Get-ToolFunctions{

    if ($UserChoice -eq "1"){
        set-executionpolicy remotesigned -Force
        Get-ToolsMenu


    }

    elseif ($UserChoice -eq "2"){
        $Global:HostIP = Read-Host "Enter IPv4 Address"
        $Global:SecondaryIP = Read-Host "Enter Secondary DNS"
        Add-NetworkSettings
        Get-ToolsMenu

    }

    elseif ($UserChoice -eq "3"){
        $Global:Hostname = Read-Host "Enter The New Hostname"
        Set-Hostname
        Restart-Computer
        Get-ToolsMenu
        

    }

    elseif ($UserChoice -eq "4"){
        $Global:HostDomain = Read-Host "Enter Domain Name"
        Add-Host
        Get-ToolsMenu

    }

    elseif ($UserChoice -eq "5"){
        Add-SecondaryDCRoles
        Get-ToolsMenu
    }

    elseif ($UserChoice -eq "6"){
        Set-FWPermissions
        Get-ToolsMenu

    }

    elseif ($UserChoice -eq "7"){
        Set-HostDNSRecords
        Get-ToolsMenu

    }

    elseif ($UserChoice -eq "8"){
        Set-HostDNSRecords
        Get-ToolsMenu
    }

    elseif ($UserChoice -eq "9"){
        Add-DHCPFailover
        Get-ToolsMenu
    }

    elseif ($UserChoice -eq "10"){
        Get-ToolsMenu

    }
    elseif ($UserChoice -eq "11"){
        Get-ToolsMenu

    }

    elseif ($UserChoice -eq "12"){
        Get-ToolsMenu

    }

    elseif ($UserChoice -eq "13"){
        Get-ToolsMenu

    }

    elseif ($UserChoice -eq "Back" -or $UserChoice -eq "back"){
        Get-TitleScreen

    }

}


#######################  Automation Menu functions ##################################



function Get-HostSettings{

  foreach ($Line in $Basefile){

    if ($env:computername -eq $Line.Hostname){
      
      [int] $Global:DeviceSelection = ($Line.Index - 1)
      $Global:HostIP = $Basefile.IPV4[$DeviceSelection]
      $Global:Hostname = $Basefile.Hostname[$DeviceSelection]
      $GLobal:Subnet = $Basefile.Subnet[$DeviceSelection]
      $Global:GatewayIP = $Basefile.Gateway[$DeviceSelection]
      $Global:Mask = $Basefile.Mask[$DeviceSelection]
      $Global:DHCPStart = $Basefile.DHCPStart[$DeviceSelection]
      $Global:DHCPEnd = $Basefile.DHCPEnd[$DeviceSelection]
      $Global:VPNStart = $Basefile.VPNStart[$DeviceSelection]
      $Global:VPNEnd = $Basefile.VPNEnd[$DeviceSelection]
      $Global:Roles = $Basefile.Roles[$DeviceSelection]
      $Global:ServerRole = $Basefile.Server[$DeviceSelection]
      $Global:NetworkID = $Basefile.NetworkID[$DeviceSelection]


      if ($Basefile.Server[$DeviceSelection] -eq "Primary"){
        $Global:SecHostname = $Basefile.Hostname[$DeviceSelection + 1]
        $Global:SecondaryIP = $Basefile.IPV4[$DeviceSelection + 1]
        $Global:ScopeID = $Basefile.ScopeID[$DeviceSelection]
        }
      elseif ($Basefile.Server[$DeviceSelection] -eq "Secondary") {
        $Global:SecHostname = $Basefile.Hostname[$DeviceSelection -1 ]
        $Global:SecondaryIP = $Basefile.IPV4[$DeviceSelection - 1 ]
        $Global:ScopeID = $Basefile.ScopeID[$DeviceSelection - 1]
        }
      }
    }
  }


function Get-AutomationFunctions{

  if ($Userchoice -eq "1"){
      $Basefile | ft Index, Hostname, IPv4, Roles, Server

      try{

      $DeviceSelection = Read-Host "Enter the Index of the Device to Load the Settings"
      $DeviceSelection -= 1

      $Global:HostIP = $Basefile.IPV4[$DeviceSelection]
      $Global:Hostname = $Basefile.Hostname[$DeviceSelection]
      $GLobal:Subnet = $Basefile.Subnet[$DeviceSelection]
      $Global:GatewayIP = $Basefile.Gateway[$DeviceSelection]
      $Global:Mask = $Basefile.Mask[$DeviceSelection]
      $Global:DHCPStart = $Basefile.DHCPStart[$DeviceSelection]
      $Global:DHCPEnd = $Basefile.DHCPEnd[$DeviceSelection]
      $Global:VPNStart = $Basefile.VPNStart[$DeviceSelection]
      $Global:VPNEnd = $Basefile.VPNEnd[$DeviceSelection]
      $Global:Roles = $Basefile.Roles[$DeviceSelection]
      $Global:ServerRole = $Basefile.Server[$DeviceSelection]
      $Global:NetworkID = $Basefile.NetworkID[$DeviceSelection]

      }

      catch{

          Write-Warning "Oh darn, Something Went Wrong With the Configuration"
      }
      
      finally{

          Get-DeploymentMenu
      }
      
  }

  elseif ($Userchoice -eq "2"){

    if ($Serverrole -eq "RAS"){
      Add-RRASNetSettings
    }

    if ($Serverrole -ne "RAS"){
      Add-NetworkSettings
      
    }
      Set-HostDNS
      Set-Hostname
      Disable-IPv6
      Restart-Computer
      Get-DeploymentMenu
   }

  elseif ($Userchoice -eq "3") {

       if ($Serverrole -eq "Primary"){

          Add-PrimaryDCRoles
          Set-FWPermissions
          Get-DeploymentMenu
      }

      elseif ($Serverrole -eq "Secondary"){

          Add-SecondaryDCRoles
          Set-FWPermissions
          Write-Warning "You Are About To attach To a Primary Domain Controller, Ensure you can NSLookup the Primary before attaching"
          $NetBios = Read-Host "Enter the NETBIOS"
          Install-ADDSDomainController -Domainname "$Forest" -Credential (Get-Credential "$NetBios\Administrator")
          Get-DeploymentMenu
      }

      elseif ($Serverrole -eq "RAS"){
        Install-WindowsFeature "RemoteAccess","Routing","DirectAccess-VPN","RSAT-RemoteAccess" -IncludeManagementTools
        set-FWPermissions


        Get-DeploymentMenu
      }
  }

  elseif ($Userchoice -eq "4") {

    Set-OUPath
    Add-TopOU
    Add-OUStructure
    Add-GPOStructure
    Add-GPOValues
    Add-OUUsers
    Add-ADGroup
    $Drivesetup = Read-Host "Setup and Map Network Drives Attached to the Server? (y/n)"

    if ($Drivesetup -eq "y" -or $Drivesetup -eq "Y"){
      Add-DriveProperties
      Add-NetDrivesPath
    }

    Set-PasswordPolicy
    Set-ComputerPath
    Import-GPOBackup
    Add-NetworkFiles
    Write-Warning "All Users, OU's and GPO's have been Created Successfully"
    Get-DeploymentMenu

}

  elseif ($Userchoice -eq "5") {
      Set-HostDNSRecords
      Set-PrimaryDHCPRole
      Get-DeploymentMenu
    }

    elseif ($Userchoice -eq "6") {
      Set-HostDNSRecords
      Set-PrimaryDHCPRole
      Get-DeploymentMenu
    }
    
    
  elseif ($Userchoice -eq "7") {
      Set-HostDNSSecondary
      Get-DeploymentMenu
    }

  elseif ($Userchoice -eq "8"){
      Add-DHCPFailover
      Get-DeploymentMenu
  }

  elseif ($Userchoice -eq "9"){
      Add-DFSRoot
      Add-DFSFolders
      Get-DeploymentMenu
  }

  elseif ($Userchoice -eq "10"){
      Add-PTRRecords
      Get-DeploymentMenu
  }

  elseif ($Userchoice -eq "11"){
    $RRASLocation = Read-Host "BE CAREFUL, Is this Kelowna or Calgary? (K/C)"

    if($RRASLocation -eq "k" -or $RRASLocation -eq "K"){
      Add-KelownaRRASConnection
    }
  
    elseif($RRASLocation -eq "c" -or $RRASLocation -eq "C"){
      Add-CalgaryRRASConnection
    }
    Get-DeploymentMenu
}


  elseif ($Userchoice -eq "Back" -or $Userchoice -eq "back"){
          Get-TitleScreen

      }

}


function Get-TitleScreen { Write-Host `
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
            V.0.4

            ---------------Windows Server Tools-------------------
            ------------------------------------------------------

                    Tools:

                    --------------------------------------
                    ------------SERVER TOOLS--------------
                    
                    1. Create VM Host or Server
                    2. Automation Tools Menu


                    --------------------------------------
                    -----------DOMAIN PC TOOLS------------

                    3. Set Static Default Settings Host PC
                    4. Add a Host PC To a Domain


                    --------------------------------------
                    -------------EXTRA TOOLS---------------

                    5. Standalone Setup Tools (Incomplete)
                    6. Exit

                    
"

Get-UserSelection
Get-TitleFunctions
}



function Get-ToolsMenu{ Write-Host "






            ---------------Standalone Tools----------------------
            -----------------------------------------------------
            Type Back to Return to Automatic Deployment Tools

            Tools:

            1.  Enable Scripts on Host
            2.  Set Static Network Settings
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
Get-UserSelection
Get-ToolFunctions

}

function Get-DeploymentMenu{ 
Get-HostSettings

  Write-Output "
        ---------------Current Loaded Settings-------------------
        ---------------------------------------------------------

                   Hostname: $Hostname

                Server Role: $ServerRole

                         IP: $HostIP

                     Forest: $Forest

                      Roles: $Roles

                 DHCP Scope: $DHCPStart - $DHCPEnd

                  VPN Scope: $VPNStart - $VPNEnd

                    Partner: $Sechostname

            ----------------------------------------------
            -------------SERVER CONFIGURATION ------------

            1.  Choose Server Config
            2.  Set Server Pre-Requisites
            3.  Install and Configure Server Roles

            ----------------------------------------------
            --------------DOMAIN CONTROLLER---------------

            4.  Build the AD-DS Structure from Configs (Primary)
            5.  Set Primary DNS Records and DHCP Scope (Primary)
            6.  Set Secondary DNS Records and DHCP Scope (Secondary)
            7.  Start a DNS Zone Transfer (Secondary)
            8.  Create a DHCP Failover (DC01)

            -----------------------------------------------
            ----------------SPECIAL ROLES------------------

            9.  Start DFS Setup (DC01)
            10. Update All Pointer Records (Primary)
            11. RRAS Connection Setup


"
Get-UserSelection
Get-AutomationFunctions


}

function Get-UserSelection {
  $Global:UserChoice = Read-Host "Selection "
}


######## LOAD MENU ##########


Get-TitleScreen
