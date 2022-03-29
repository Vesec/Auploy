

function Set-ADSites{

Get-ADObject `
-SearchBase (Get-ADRootDSE).ConfigurationNamingContext `
-filter “ObjectClass -eq 'Site'” `
| Rename-ADObject -NewName Kelowna

New-ADReplicationSite -Name "Calgary"

New-ADReplicationSubnet -Name "192.168.1.0/24" -Site Kelowna
New-ADReplicationSubnet -Name "192.168.2.0/24" -Site Calgary

Move-ADDirectoryServer -Identity "DC03-Calgary" -Site "Calgary"
Move-ADDirectoryServer -Identity "DC04-Calgary" -Site "Calgary"

}



