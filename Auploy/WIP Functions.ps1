

function Get-ISOList {
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

    $Global:ISOValues = @()
    cd "C:\"
    $ISOList = ls *.ISO -Recurse -ErrorAction 'SilentlyContinue'

    for ($i = 0; $i -lt $ISOList.Length; $i++) {
        $ISO = $ISOList[$i]
        $ISOValues += [string] $ISO
        write-host $ISOlist
    }
    
    #Select-Menu
}

function Select-Menu{
    [string] $SelectISO = `
    "
    ██████ ▓█████  ██▓    ▓█████  ▄████▄  ▄▄▄█████▓    ██▓  ██████  ▒█████  
    ▒██    ▒ ▓█   ▀ ▓██▒    ▓█   ▀ ▒██▀ ▀█  ▓  ██▒ ▓▒   ▓██▒▒██    ▒ ▒██▒  ██▒
    ░ ▓██▄   ▒███   ▒██░    ▒███   ▒▓█    ▄ ▒ ▓██░ ▒░   ▒██▒░ ▓██▄   ▒██░  ██▒
      ▒   ██▒▒▓█  ▄ ▒██░    ▒▓█  ▄ ▒▓▓▄ ▄██▒░ ▓██▓ ░    ░██░  ▒   ██▒▒██   ██░
    ▒██████▒▒░▒████▒░██████▒░▒████▒▒ ▓███▀ ░  ▒██▒ ░    ░██░▒██████▒▒░ ████▓▒░
    ▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ▒░▓  ░░░ ▒░ ░░ ░▒ ▒  ░  ▒ ░░      ░▓  ▒ ▒▓▒ ▒ ░░ ▒░▒░▒░ 
    ░ ░▒  ░ ░ ░ ░  ░░ ░ ▒  ░ ░ ░  ░  ░  ▒       ░        ▒ ░░ ░▒  ░ ░  ░ ▒ ▒░ 
    ░  ░  ░     ░     ░ ░      ░   ░          ░          ▒ ░░  ░  ░  ░ ░ ░ ▒  
          ░     ░  ░    ░  ░   ░  ░░ ░                   ░        ░      ░ ░  
                                   ░                                          

    "
    Write-Host $SelectIso
    <#
   # $Selection = Create-Menu `
    #-MenuTitle "$SelectISO" `
    #-MenuOptions `
    #"Pathggggggggggggggggggggggggggggggggg",`
    #"Pathggggggggggggggggggggggggggggggggggggggggggggggg",`
    "Pathgggg",`
    "Path",`
    "Path" `
    -Columns 1 `
    -MaximumColumnWidth 300 `
    -ShowCurrentSelection $True
    



    #$ISOValues[0],$ISOValues[1],$ISOValues[2],$ISOValues[3],$ISOValues[4] -Columns 1 -MaximumColumnWidth 15 -ShowCurrentSelection $True

    Switch($Selection){
    0 {Write-Host "This is the action for option 1"}
    1 {Write-Host "This is the action for option 2"}
    2 {Write-Host "This is the action for option 3"}
    3 {Write-Host "This is the action for option 4"}
    4 {Write-Host "This is the action for option 5"}
    }
    #>

}


#Get-ISOList
#Select-Menu