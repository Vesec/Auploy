#$Global:NetworkConfig = Import-CSV "C:\Users\Administrator\Desktop\NetworkSettings.csv"



#Rename-Computer -NewName "$Hostname"

## Calgary
#Install-WindowsFeature "RemoteAccess","Routing","DirectAccess-VPN","RSAT-RemoteAccess"

function Add-CalgaryRRASConnection{
install-Remoteaccess -Computername "RRAS-Calgary" -vpntype VPNS2S -IPAddressRange "192.168.2.50","192.168.2.99" -Legacy
Add-VPnS2SInterface -Name "RRAS-Kelowna" -Protocol IKEv2 -Destination 10.10.1.1 -AuthenticationMethod PresharedKey -IPV4Subnet 191.168.1.0/24:1 -Password "P@ssw0rd!!"
Set-VpnServerIPsecConfiguration -CustomPolicy -EncryptionMethod AES256 -AuthenticationTransformConstants SHA196 -CipherTransformConstants AES256 -IntegrityCheckMethod SHA1


}
##Kelowna

function Add-KelownaRRASConnection{
install-Remoteaccess -Computername "RRAS-Kelowna" -vpntype VPNS2S -IPAddressRange "192.168.1.50","192.168.1.99" -Legacy
Add-VPnS2SInterface -Name "RRAS-Calgary" -Protocol IKEv2 -Destination 10.10.1.5 -AuthenticationMethod PresharedKey -IPV4Subnet 191.168.2.0/24:1 -Password "P@ssw0rd!!"
Set-VpnServerIPsecConfiguration -CustomPolicy -EncryptionMethod AES256 -AuthenticationTransformConstants SHA196 -CipherTransformConstants AES256 -IntegrityCheckMethod SHA1

}

function Add-RRASNetSettings{

$AutoIndex = Get-NetAdapter -Name * -Physical
[int] $LANIntIndex = $AutoIndex.InterfaceIndex[0]
[int] $WANIntIndex = $AutoIndex.InterfaceIndex[1]
$LANName = $AutoIndex.Name[0]
$WANNAme = $AutoIndex.Name[1]


foreach($Line in $NetworkConfig){

    $HostIP = $Line.IPAddress
    $Mask = $Line.Mask
    $GatewayIP = $Line.Gateway

    if($Line.NIC -eq "LAN" -and $Line.Hostname -eq $env:COMPUTERNAME){

        New-NetIPAddress -InterfaceIndex $LANIntIndex -IPAddress $HostIP -Prefixlength $Mask `
        -AddressFamily IPv4

        Rename-NetAdapter -Name $LANName -NewName "LAN"
        
    }

    if($Line.NIC -eq "WAN" -and $Line.Hostname -eq $env:COMPUTERNAME){

        New-NetIPAddress -InterfaceIndex $WANIntIndex -IPAddress $HostIP -Prefixlength $Mask `
        -DefaultGateway "$GatewayIP" -AddressFamily IPv4

        Rename-NetAdapter -Name $WANName -NewName "WAN"
        
    }
}

}

#Add-RRASNetSettings

#Add-CalgaryRRASConnection