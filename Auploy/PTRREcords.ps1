

<#
    if($env:USERNAME -eq "DC03-Calgary"){

    Add-DnsServerPrimaryZone -NetworkID "192.168.2.0/24" -ReplicationScope "Forest"

    }
#>

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


Add-PTRRecords