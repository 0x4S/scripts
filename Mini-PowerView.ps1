<# 
Mini-PowerView.ps1
A lightweight PowerView replacement using only AD & GroupPolicy modules.
#>

function Show-Menu {
    Write-Host "`n=== Mini PowerView Replacement ===`n" -ForegroundColor Cyan
    Write-Host " 1. List all users"
    Write-Host " 2. AS-REP roastable users (Preauth not required)"
    Write-Host " 3. Kerberoastable users (SPN set)"
    Write-Host " 4. Disabled accounts"
    Write-Host " 5. Password never expires"
    Write-Host " 6. Password not required"
    Write-Host " 7. Locked out accounts"
    Write-Host " 8. Domain Admins members"
    Write-Host " 9. All groups"
    Write-Host "10. All computers"
    Write-Host "11. Users with description set"
    Write-Host "12. Organizational Units (OUs)"
    Write-Host "13. Domain trusts"
    Write-Host "14. Forest trusts"
    Write-Host "15. Group Policies"
    Write-Host "16. Exit"
}

function Run-Query($choice) {
    switch ($choice) {
        1 { Get-ADUser -Filter * -Properties samaccountname | Select samaccountname }
        2 { Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" -Properties samaccountname,userprincipalname }
        3 { Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties samaccountname,serviceprincipalname }
        4 { Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=2)" -Properties samaccountname }
        5 { Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=65536)" -Properties samaccountname }
        6 { Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=32)" -Properties samaccountname }
        7 { Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=16)" -Properties samaccountname }
        8 { Get-ADGroupMember -Identity "Domain Admins" -Recursive | Get-ADUser -Properties samaccountname | Select samaccountname }
        9 { Get-ADGroup -Filter * | Select Name,GroupCategory,GroupScope }
       10 { Get-ADComputer -Filter * -Properties dnshostname,operatingsystem }
       11 { Get-ADUser -Filter * -Properties description | Where-Object { $_.Description -ne $null } | Select samaccountname, description }
       12 { Get-ADOrganizationalUnit -Filter * -Properties * }
       13 { Get-ADTrust -Filter * }
       14 { (Get-ADForest).Trusts }
       15 { Get-GPO -All | Select DisplayName,Id,CreationTime,ModificationTime }
       16 { Write-Host "Exiting..." -ForegroundColor Yellow; exit }
        default { Write-Host "Invalid choice" -ForegroundColor Red }
    }
}

# Main loop
do {
    Show-Menu
    $choice = Read-Host "Select an option (1-16)"
    Run-Query $choice
} while ($true)
