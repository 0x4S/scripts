<#
Mini-PowerView.ps1
A lightweight PowerView replacement using only Active Directory & Group Policy modules.
Optimised for speed and usability:
- Progress bars removed
- Output flushed immediately using Out-Host
- Direct LDAP queries used where possible
- Privilege indicators updated
- Graceful exit on Ctrl+C
#>

function Show-Menu {
    Write-Host "`n=== Mini PowerView Replacement ===`n" -ForegroundColor Cyan

    # Legend (colour-coded and tagged)
    Write-Host "Legend:" -ForegroundColor White
    Write-Host -NoNewline "    [G] " -ForegroundColor Green;   Write-Host "Default domain user privileges"
    Write-Host -NoNewline "    [Y] " -ForegroundColor Yellow;  Write-Host "May require elevated privileges (depending on domain configuration)"
    Write-Host -NoNewline "    [R] " -ForegroundColor Red;     Write-Host "Often requires elevated privileges (e.g. Domain Admin)"

    # Menu options
    Write-Host "`n [G]  1. List all users" -ForegroundColor Green
    Write-Host " [G]  2. AS-REP roastable users (Preauth not required)" -ForegroundColor Green
    Write-Host " [G]  3. Kerberoastable users (SPN set)" -ForegroundColor Green
    Write-Host " [G]  4. Disabled accounts" -ForegroundColor Green
    Write-Host " [G]  5. Password never expires" -ForegroundColor Green
    Write-Host " [G]  6. Password not required" -ForegroundColor Green
    Write-Host " [G]  7. Locked out accounts" -ForegroundColor Green
    Write-Host " [Y]  8. Domain Admins members" -ForegroundColor Yellow
    Write-Host " [G]  9. All groups" -ForegroundColor Green
    Write-Host " [G] 10. All computers" -ForegroundColor Green
    Write-Host " [G] 11. Users with description set" -ForegroundColor Green
    Write-Host " [G] 12. Organisational Units (OUs)" -ForegroundColor Green
    Write-Host " [R] 13. Domain trusts" -ForegroundColor Red
    Write-Host " [R] 14. Forest trusts" -ForegroundColor Red
    Write-Host " [Y] 15. Group Policies" -ForegroundColor Yellow
    Write-Host "      16. Exit" -ForegroundColor White

    Write-Host "`nNote: You can press Ctrl+C to stop and exit the script at any time." -ForegroundColor Yellow
}

function Prompt-Export {
    [CmdletBinding()]
    param(
        [string]$BaseName,
        $Data
    )
    $exportChoice = Read-Host "Export results to CSV file? (y/n)"
    if ($exportChoice -match '^(Y|y)') {
        $dateStamp  = (Get-Date).ToString('yyyyMMdd')
        $domainName = (Get-ADDomain).NetBIOSName.ToLower()
        $fileName = "${BaseName}_${domainName}_${dateStamp}.csv"
        $Data | Export-Csv -Path $fileName -NoTypeInformation
        Write-Host "Results exported to $fileName" -ForegroundColor Green
    }
}

function Run-Query {
    param([string]$choice)
    switch ($choice) {
        "1" {
            $baseName = "AllUsers"
            $results  = Get-ADUser -Filter * -Properties SamAccountName | Select-Object SamAccountName
            $results | Out-Host
            Prompt-Export -BaseName $baseName -Data $results
        }
        "2" {
            $baseName = "ASREP_RoastableUsers"
            $results  = Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" `
                                 -Properties SamAccountName, UserPrincipalName |
                       Select-Object SamAccountName, UserPrincipalName
            $results | Out-Host
            Prompt-Export -BaseName $baseName -Data $results
        }
        "3" {
            $baseName = "KerberoastableUsers"
            $results  = Get-ADUser -LDAPFilter "(&(objectCategory=person)(servicePrincipalName=*))" `
                                 -Properties SamAccountName, ServicePrincipalName |
                       Select-Object SamAccountName, @{Name='ServicePrincipalName'; Expression={ ($_.ServicePrincipalName -join "; ") }}
            $results | Out-Host
            Prompt-Export -BaseName $baseName -Data $results
        }
        "4" {
            $baseName = "DisabledAccounts"
            $results  = Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=2)" `
                                 -Properties SamAccountName | Select-Object SamAccountName
            $results | Out-Host
            Prompt-Export -BaseName $baseName -Data $results
        }
        "5" {
            $baseName = "PasswordNeverExpires"
            $results  = Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=65536)" `
                                 -Properties SamAccountName | Select-Object SamAccountName
            $results | Out-Host
            Prompt-Export -BaseName $baseName -Data $results
        }
        "6" {
            $baseName = "PasswordNotRequired"
            $results  = Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=32)" `
                                 -Properties SamAccountName | Select-Object SamAccountName
            $results | Out-Host
            Prompt-Export -BaseName $baseName -Data $results
        }
        "7" {
            $baseName = "LockedOutAccounts"
            $results  = Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=16)" `
                                 -Properties SamAccountName | Select-Object SamAccountName
            $results | Out-Host
            Prompt-Export -BaseName $baseName -Data $results
        }
        "8" {
            $baseName = "DomainAdminsMembers"
            $members  = Get-ADGroupMember -Identity "Domain Admins" -Recursive
            $userMembers = $members | Where-Object { $_.objectClass -eq 'user' }
            $results = $userMembers | Get-ADUser -Properties SamAccountName | Select-Object SamAccountName
            $results | Out-Host
            Prompt-Export -BaseName $baseName -Data $results
        }
        "9" {
            $baseName = "AllGroups"
            $results  = Get-ADGroup -Filter * -Properties GroupCategory, GroupScope |
                       Select-Object Name, GroupCategory, GroupScope
            $results | Out-Host
            Prompt-Export -BaseName $baseName -Data $results
        }
        "10" {
            $baseName = "AllComputers"
            $results  = Get-ADComputer -Filter * -Properties DNSHostName, OperatingSystem |
                       Select-Object Name, DNSHostName, OperatingSystem
            $results | Out-Host
            Prompt-Export -BaseName $baseName -Data $results
        }
        "11" {
            $baseName = "UsersWithDescription"
            $results  = Get-ADUser -LDAPFilter "(description=*)" -Properties SamAccountName, Description |
                       Select-Object SamAccountName, Description
            $results | Out-Host
            Prompt-Export -BaseName $baseName -Data $results
        }
        "12" {
            $baseName = "OrganizationalUnits"
            $results  = Get-ADOrganizationalUnit -Filter * |
                       Select-Object Name, DistinguishedName
            $results | Out-Host
            Prompt-Export -BaseName $baseName -Data $results
        }
        "13" {
            $baseName = "DomainTrusts"
            $results  = Get-ADTrust -Filter *
            $results | Out-Host
            Prompt-Export -BaseName $baseName -Data $results
        }
        "14" {
            $baseName = "ForestTrusts"
            $results  = (Get-ADForest).Trusts
            $results | Out-Host
            Prompt-Export -BaseName $baseName -Data $results
        }
        "15" {
            $baseName = "GroupPolicies"
            $results  = Get-GPO -All | Select-Object DisplayName, Id, CreationTime, ModificationTime
            $results | Out-Host
            Prompt-Export -BaseName $baseName -Data $results
        }
        "16" {
            return
        }
        default {
            Write-Host "Invalid choice, please try again." -ForegroundColor Red
        }
    }
}

function Enable-GracefulExit {
    trap [System.Management.Automation.PipelineStoppedException] {
        Write-Host "Exiting gracefully (Ctrl+C pressed)." -ForegroundColor Yellow
        exit
    }
}

# Start
Enable-GracefulExit
do {
    Show-Menu
    $choice = Read-Host "Select an option (1-16)"
    if ($choice -eq '16') {
        Write-Host "Exiting..." -ForegroundColor Yellow
        break
    }
    Run-Query $choice
} while ($true)
