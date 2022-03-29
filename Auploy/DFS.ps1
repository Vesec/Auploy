




function Add-DFSRoot{

New-Item -Path "C:\DFSRoots\Shares" -ItemType Directory  -Force | Out-Null
New-SmbShare -Name ShareAccess -path 'C:\DFSRoots\Shares' -ChangeAccess "Domain Users" -FullAccess "Domain Admins"
New-DfsnRoot -TargetPath "\\DC01-KELOWNA\ShareAccess" -Type DomainV2 -Path "\\Int.Raudz.Com\ShareAccess" -GrantAdminAccounts "GrantAdmin" -EnableRootScalability $True
}



function Add-DFSFolders{

$Drive = "Finance"#, "Internal", "IT Resources", "Marketing", "HR"

#foreach($Drive in $DriveArray){

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


New-DfsReplicationGroup -GroupName "Raudz Network Drives" | `
New-DfsReplicatedFolder -FolderName "$Drive" | `
Add-DfsrMember -ComputerName "DC01-Kelowna","DC02-Kelowna" | `
Format-Table dnsname,groupname -auto -wrap

Add-DfsrConnection -GroupName "Raudz Network Drives" -SourceComputerName "DC01-Kelowna" `
-DestinationComputerName "DC02-Kelowna" | Format-Table *name -wrap -auto

Set-DfsrMembership -GroupName "Raudz Network Drives" -FolderName "$Drive" -ContentPath "$Letter" `
-ComputerName "DC01-Kelowna" -PrimaryMember $True -StagingPathQuotaInMB 16384 -Force | `
Format-Table *name,*path,primary* -auto -wrap

Set-DfsrMembership -GroupName "Raudz Network Drives" -FolderName "$Drive" -ContentPath "$Letter" `
-ComputerName "DC02-Kelowna" -StagingPathQuotaInMB 16384 -Force | `
Format-Table *name,*path,primary* -autosize -wrap

New-DfsnFolder `
-Path "\\Raudz\ShareAccess\$Drive" `
-TargetPath "\\DC01-KELOWNA\$Drive" `
-EnableTargetFailback $True

}


Add-DFSRoot
Add-DFSFolders



