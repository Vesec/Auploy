

$Global:Drivemap = import-csv "C:\Users\Owner\Documents\Auploy\Settings\Drives\DriveMap.csv"
function Add-DriveProperties{
    diskpart.exe /s "$AuployPath\Settings\Drives\ActivateDrives.txt"
}

function Add-NetworkDrivePath{
    New-smbshare -Name "HR" -Path "H:\" -ChangeAccess "Executives", "HR", "IT Admin", "Administration"  -NoAccess "KEL\20220008", "KEL\20220009"
    New-smbshare -Name "Finance" -Path "F:\" -ChangeAccess "Executives", "IT Admin" -NoAccess "KEL\20220007", "KEL\20220009"
    New-smbshare -Name "Internal" -Path "I:\" -ChangeAccess "Executives", "Employees", "IT Admin", "IT Tech", "Administration", "HR"
    New-smbshare -Name "Marketing" -Path "M:\" -ChangeAccess "Executives", "IT Admin", "IT Tech"
    New-smbshare -Name "IT Resources" -Path "Z:\" -ChangeAccess "Executives", "IT Admin", "IT Tech"
    
    <#
    foreach ($Drive in $Drivemap){
        $Letter = $Drive.Letter
        $DriveName = $Drive.Name
        $Groups = $Drive.Groups
        $Exclusions = $Drive.Exclude
        Write-Host $Letter $DriveName $Groups

        if ($Drivemap.Exclude -eq ""){
        #New-smbshare -Name "$DriveName" -Path "${Letter}:\" -ChangeAccess $Groups
        }
        else{
        #New-smbshare -Name "$DriveName" -Path "${Letter}:\" -ChangeAccess $Groups -NoAccess $Exclusions
        }
    }
    #>
}
#Add-DriveProperties
#Add-NetworkDrivePath



#############    SERVER   ####################

New-smbshare -Name "HR" -Path "H:\" -ChangeAccess "Executives", "HR", "IT Admin", "Administration"  -NoAccess "KEL\20220008", "KEL\20220009"
New-smbshare -Name "Finance" -Path "F:\" -ChangeAccess "Executives", "IT Admin" -NoAccess "KEL\20220007", "KEL\20220009"
New-smbshare -Name "Internal" -Path "I:\" -ChangeAccess "Executives", "Employees", "IT Admin", "IT Tech", "Administration", "HR"
New-smbshare -Name "Marketing" -Path "M:\" -ChangeAccess "Executives", "IT Admin", "IT Tech"
New-smbshare -Name "IT Resources" -Path "Z:\" -ChangeAccess "Executives", "IT Admin", "IT Tech"

############ GPO ONLOAD SCRIPT ################

New-SmbMapping -LocalPath 'M:' -RemotePath '\\DC01\Marketing'
New-SmbMapping -LocalPath 'F:' -RemotePath '\\DC01\Finance'
New-SmbMapping -LocalPath 'I:' -RemotePath '\\DC01\Internal'
New-SmbMapping -LocalPath 'H:' -RemotePath '\\DC01\HR'
New-SmbMapping -LocalPath 'Z:' -RemotePath '\\DC01\IT Resources'

######## CMD ??? #############
net use Z: \\DC01\IT Resources
net use H: \\DC01\HR
net use I: \\DC01\Internal
net use F: \\DC01\Finance
net use M: \\DC01\Marketing


