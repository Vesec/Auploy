$Global:UserID = $env:Username



function Get-UserGroup{

if ($UserID -gt 20220000 -and $UserID -lt 2022010){
    $Global:Exclusions = ""
    $Global:Usergroup = "Executives"
}

if ($UserID -gt 2022009 -and $UserID -lt 20220014){
    $Global:Exclusions = ""
    $Global:Usergroup = "HR"
}

if ($UserID -gt 20220015 -and $UserID -lt 20220020){
    $Global:Exclusions = "20220018","20220019"
    Add-ITDrives
}

if ($UserID -gt 20220019){
    $Global:Exclusions = 
    $Global:Usergroup = "Employees"
}

}



function Add-ITDrives{

If ($UserID -notin $Exclusions){
    New-SmbMapping -LocalPath 'H:' -RemotePath '\\DC03-Calgary\HR'
    New-SmbMapping -LocalPath 'F:' -RemotePath '\\DC03-Calgary\Finance'
    $Shell.NameSpace("H:\").Self.Name = 'Human Resources'
    $Shell.NameSpace("F:\").Self.Name = 'Finance'
    }

    New-SmbMapping -LocalPath 'Z:' -RemotePath '\\DC03-Calgary\IT Resources'
    New-SmbMapping -LocalPath 'I:' -RemotePath '\\DC03-Calgary\Internal'
    New-SmbMapping -LocalPath 'M:' -RemotePath '\\DC03-Calgary\Marketing'
    $Shell.NameSpace("Z:\").Self.Name = 'IT Resources'
    $Shell.NameSpace("I:\").Self.Name = 'Internal'

    }


    Get-UserGroup
