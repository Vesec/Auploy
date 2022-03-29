
$Global:UserID = $env:Username

$Global:FinanceExclusion = "20220007","20220009"
$Global:HRExclusion = "20220018","20220019","20220009","20220008"
$GLobal:MarketingExclusions = @()
$Global:ITResourcesExclusions = @()
$Global:InternalExclusions = @()

function Get-UserGroup{

<#
.SYNOPSIS
Sets and Array of Global Variables based on user Group Segregation for Adding Network Drive Mapping.

.DESCRIPTION
Compares Employee ID to a Range of Values to determine which Drives should be accessible to the individual User, 
and then adds named values to $DriveArray that are used to add each drive in Add-NetworkDriveMapping.

Author: Tyler Dorner
Date: Mar 26th 2022
#>


if ($UserID -gt 20220000 -and $UserID -lt 20220010){
    $Global:DriveArray = "HR","Finance","Internal","Marketing"
}

elseif ($UserID -gt 20220009 -and $UserID -lt 20220014){
    $Global:DriveArray = "HR","Internal"
}

elseif ($UserID -gt 20220015 -and $UserID -lt 20220018){
    $Global:DriveArray = "Finance","HR","Internal","Marketing","It Resources"
}

elseif ($UserID -gt 20220017 -and $UserID -lt 20220020){
    $Global:DriveArray = "Marketing","Internal","IT Resources"

}

elseif ($UserID -gt 20220019){
    $Global:DriveArray = "Internal"

}

}

function Add-NetworkDriveMapping{

<#
.SYNOPSIS
Uses Global Variables to Add Each Drive in a Specified Array.

.DESCRIPTION
Uses Global Variables from Get-UserGroup to map the drives that the User is permitted to Access. 
Each Variable in the Array $DriveArray is then added if the User is not identified in an Exclusion Array.

Author: Tyler Dorner
Date: Mar 26th 2022

#>


$Shell = New-Object -com Shell.Application

If ($UserID -notin $FinanceExclusion -and "Finance" -in $DriveArray){
        New-SmbMapping -LocalPath 'F:' -RemotePath '\\Raudz\ShareAccess\Finance'
        $Shell.NameSpace("F:\").Self.Name = 'Finance'
    }
    
If ($UserID -notin $HRExclusion -and "HR" -in $DriveArray){

        New-SmbMapping -LocalPath 'H:' -RemotePath '\\Raudz\ShareAccess\HR'
        $Shell.NameSpace("H:\").Self.Name = 'Human Resources'  
    }

If ($UserID -notin $InternalExclusion -and "Internal" -in $DriveArray){
        New-SmbMapping -LocalPath 'I:' -RemotePath '\\Raudz\ShareAccess\Internal'
        $Shell.NameSpace("I:\").Self.Name = 'Internal'  
    }

If ($UserID -notin $MarketingExclusion -and "Marketing" -in $DriveArray){
        New-SmbMapping -LocalPath 'M:' -RemotePath '\\Raudz\ShareAccess\Marketing'
        $Shell.NameSpace("M:\").Self.Name = 'Marketing'  
    }

If ($UserID -notin $ITResourcesExclusion -and "IT Resources" -in $DriveArray){
        New-SmbMapping -LocalPath 'Z:' -RemotePath '\\Raudz\ShareAccess\IT Resources'
        $Shell.NameSpace("Z:\").Self.Name = 'IT Resources'  
    }
    
}

Get-UserGroup
Add-NetworkDriveMapping
