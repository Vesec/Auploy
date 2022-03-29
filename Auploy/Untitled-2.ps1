



install-Remoteaccess -Computername "RRAS-Calgary" -vpntype VPNS2S -IPAddressRange "192.168.2.50","192.168.2.99" -Legacy
Add-VPnS2SInterface -Name "RRAS-Kelowna" -Protocol IKEv2 -Destination 10.10.1.1 -AuthenticationMethod PSKOnly -IPV4Subnet 191.168.1.0/24:1 -SharedSecret "Deadmau5!!"