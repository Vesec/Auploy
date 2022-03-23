

$Scriptpath = $MyInvocation.MyCommand.Path
[int] $NameLength = ($MyInvocation.MyCommand.Name).length + 8
$Global:AuployPath = $Scriptpath -replace ".{$NameLength}$"
$Global:Basefile = Import-Csv "$AuployPath\Settings\Host\Basefile.csv"

$Global:TopOU = $Basefile.TopOU[0]
$Global:Password = $Basefile.Password[0]
$Global:HostIP = $Basefile.IPV4[0]
$Global:SecondaryIP = $Basefile.IPV4[1]
$Global:Hostname = $Basefile.Hostname[2]
$Global:SecHostname = $Basefile.Hostname[3]
$GLobal:Subnet = $Basefile.Subnet[0]
$Global:GatewayIP = $Basefile.Gateway[0]
$Global:Mask = $Basefile.Mask[0]
$Global:VMHDDSize = 0 + 120GB
$Global:DHCPStart = $Basefile.Start[0]
$Global:DHCPEnd = $Basefile.End[0]
$Global:DNSReverse = $Basefile.NetworkID[0]
$Global:Forest = $Basefile.Forest[0]
$Global:VMSwitch = $Basefile.Switch[0]
$Global:Roles = $Basefile.Roles[0]
$Global:DHCPStart = $Basefile.DHCPStart[0]
$Global:DHCPEnd = $Basefile.DHCPEnd[0]
$Global:VPNStart = $Basefile.VPNStart[0]
$Global:VPNEnd = $Basefile.VPNEnd[0]


function Get-DeploymentMenu{ 


    Write-Output "

            






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

            ---------------Automation Tools Menu-------------------


            Current Loaded Settings


            Hostname: $Hostname
            Server Role: $ServerRole
            IP: $HostIP
            Forest: $Forest
            Roles : $Roles
            DHCP Scope: $DHCPStart - $DHCPEnd
            VPN Scope : $VPNStart - $VPNEnd

            Options:

            1.  Select a Pre-built Server Configuration
            2.  Manually Set Server Config Variables
            3.  Set Static Default Settings for a Server
            4.  Install and Configure Server Roles
            5.  Set Primary DNS Records
            6.  Start a DNS Zone Transfer
            7.  Build the AD-DS Structure from Configs
            8.  Create a DHCP Failover
            9.  Start RAS Setup
            10. Start DFS Setup

            Type 'Back' to Return to The Title Menu

"
Get-Selection


}


function Get-Selection {
  $Global:UserUser$Userchoice = Read-Host "Selection "
  Get-AutomationMenu

}

function Get-AutomationMenu{

    if ($Userchoice -eq "1"){
        $Basefile | ft Index, Hostname, IPv4, Roles

        try{
        $DeviceSelection = Read-Host "Enter the Index of the Device to Load the Settings"
        $DeviceSelection -= 1
        $Global:HostIP = $Basefile.IPV4[$DeviceSelection]
        $Global:SecondaryIP = $Basefile.IPV4[$DeviceSelection]
        $Global:Hostname = $Basefile.Hostname[$DeviceSelection]
        $Global:SecHostname = $Basefile.Hostname[$DeviceSelection]
        $GLobal:Subnet = $Basefile.Subnet[$DeviceSelection]
        $Global:GatewayIP = $Basefile.Gateway[$DeviceSelection]
        $Global:Mask = $Basefile.Mask[$DeviceSelection]
        $Global:DHCPStart = $Basefile.DHCPStart[$DeviceSelection]
        $Global:DHCPEnd = $Basefile.DHCPEnd[$DeviceSelection]
        $Global:VPNStart = $Basefile.VPNStart[$DeviceSelection]
        $Global:VPNEnd = $Basefile.VPNEnd[$DeviceSelection]
        $Global:Roles = $Basefile.Roles[$DeviceSelection]
        $Global:ServerRole = $Basefile.Server[$DeviceSelection]
        }
        catch{
            Write-Warning "Oh Heck, Something Went Wrong With the Configuration"
        }
        finally{
            Get-DeploymentMenu
        }
    }

    elseif ($Userchoice -eq "2"){
        $Global:HostIP = Read-Host "Enter the Host IP"
        $Global:SecondaryIP = Read-Host "Enter the Secondary IP"
        $Global:Hostname = Read-Host "Enter the Hostname"
        $Global:SecHostname = Read-Host "Enter the Secondary Hostname"
        $GLobal:Subnet = Read-Host "Enter the Subnet Mask"
        $Global:GatewayIP = Read-Host "Enter the Gateway IP"
        $Global:Mask = Read-Host "Enter the Mask /xx "
        $Global:DHCPStart = Read-Host "Enter the DHCP Scope Start"
        $Global:DHCPEnd = Read-Host "Enter the DHCP Scope End"
        $Global:VPNStart = Read-Host "Enter the VPN Scope Start"
        $Global:VPNEnd = Read-Host "Enter the VPN Scope End"
        Get-DeploymentMenu
    }


    elseif ($Userchoice -eq "3"){
        Add-NetworkSettings
        Set-Hostname
        Disable-IPv6
        Restart-Computer
        Get-AutomationMenu
     }

    elseif ($Userchoice -eq "4") {

         if ($Serverrole -eq "Primary"){

            Add-PrimaryADRoles
            Set-FWPermissions
            Set-DHCPRole
            Get-AutomationMenu
        }

        elseif ($Serverrole -eq "Secondary"){

            Add-SecondaryADRoles
            Set-FWPermissions
            $NetBios = Read-Host "Enter the NETBIOS"
            Install-ADDSDomainController -Domainname "$Forest" -Credential (Get-Credential "$NetBios\Administrator")
            Get-AutomationMenu
        }

        elseif ($Serverrole -eq "RAS"){

        }
    }

    elseif ($Userchoice -eq "5") {
        Set-DNSRecords
        Get-AutomationMenu
      }
      
      
    elseif ($Userchoice -eq "6") {
        Set-DNSSecondary
        Get-AutomationMenu
      }


    elseif ($Userchoice -eq "7") {

        Set-OUPath
        Add-TopOU
        Add-OUStructure
        Add-GPOStructure
        Add-GPOValues
        Add-OUUsers
        Add-ADGroup
        Add-DriveProperties
        Add-NetworkSettingsDrivePath
        Set-PasswordPolicy
        Set-ComputerPath
        Set-DHCPRole
        Get-AutomationMenu
    
    }

    elseif ($Userchoice -eq "8"){
        Add-DHCPFailover
        Get-AutomationMenu
    }

    elseif ($Userchoice -eq "9"){

        Get-AutomationMenu
    }

    elseif ($Userchoice -eq "10"){
 
        Get-AutomationMenu
    }

    elseif ($Userchoice -eq "Back" -or $Userchoice -eq "back"){
            Get-TitleScreen

        }

}

Get-DeploymentMenu

<#
$Check123 = $DeviceSettings.Roles
write-host $Check123
#>