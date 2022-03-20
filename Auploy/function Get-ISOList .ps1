

function Get-ISOList {

    cd "C:\"
    $ISOList = ls *.ISO -Recurse -ErrorAction 'SilentlyContinue'

    for ($i = 0; $i -lt $ISOList.Length; $i++) {
        $ISO = $ISOList[$i]
    }

    $ISONumber = Read-Host "Select ISO Number"
    $selectedISO = $ISOList[$ISONumber]
    $selectedISO
}
