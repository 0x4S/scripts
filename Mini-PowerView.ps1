<#
Mini-PowerView.ps1
A lightweight PowerView replacement using only Active Directory & Group Policy modules.
Now includes an option to export query results to CSV files, and shows progress indicators for long-running queries.
#>

function Show-Menu {
    # Display the menu of available options with colour-coded and tagged privilege indicators.
    # Legend: [G] = Green = default domain user privileges
    #         [Y] = Yellow = may need elevated privileges
    #         [R] = Red = often requires elevated privileges

    Write-Host "`n=== Mini PowerView Replacement ===`n" -ForegroundColor Cyan

    # Legend (colour-coded and tagged)
    Write-Host "Legend:" -ForegroundColor White
    Write-Host -NoNewline "    [G] " -ForegroundColor Green; Write-Host "Default domain user privileges"
    Write-Host -NoNewline "    [Y] " -ForegroundColor Yellow; Write-Host "May require elevated privileges"
    Write-Host -NoNewline "    [R] " -ForegroundColor Red; Write-Host "Often requires elevated privileges"

    # Menu options with tags and colour
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
}

function Prompt-Export {
    [CmdletBinding()]
    param(
        [string]$BaseName,   # Base name for the query (used in filename)
        $Data               # Data to export (object or array of objects)
    )
    # Prompt the user whether to export the results to a CSV file
    $exportChoice = Read-Host "Export results to CSV file? (y/n)"
    if ($exportChoice -match '^(Y|y)') {
        # Get current date as YYYYMMDD for timestamp in filename
        $dateStamp  = (Get-Date).ToString('yyyyMMdd')
        # Get the NetBIOS (short) name of the current domain in lowercase for the filename
        $domainName = (Get-ADDomain).NetBIOSName.ToLower()
        # Construct the CSV file name (e.g. AllUsers_mycorp_20250906.csv)
        $fileName = "${BaseName}_${domainName}_${dateStamp}.csv"
        # Export the data to CSV in the current directory without type information
        $Data | Export-Csv -Path $fileName -NoTypeInformation
        Write-Host "Results exported to $fileName" -ForegroundColor Green
    }
}

function Run-Query {
    param([string]$choice)
    # Execute the selected query, display results, and prompt for CSV export. Show progress for long-running queries.
    switch ($choice) {
        "1" {
            # Option 1: List all user accounts
            $baseName = "AllUsers"
            # Retrieve all user accounts and display progress (this may take a while in large domains)
            $allUsers = Get-ADUser -Filter * -Properties samaccountname
            $total    = $allUsers.Count
            $counter  = 0
            $results  = @()
            foreach ($user in $allUsers) {
                $counter++
                Write-Progress -Activity "Listing all users" -Status "Processing $counter of $total users..." -PercentComplete ($counter / $total * 100)
                # Collect only the SamAccountName for each user
                $results += [PSCustomObject]@{ SamAccountName = $user.SamAccountName }
            }
            # Complete the progress bar
            Write-Progress -Activity "Listing all users" -Completed
            $results  # Display results on screen
            Prompt-Export -BaseName $baseName -Data $results  # Offer to export to CSV
        }
        "2" {
            # Option 2: Find AS-REP roastable users (Preauth not required)
            $baseName = "ASREP_RoastableUsers"
            # Retrieve all users to identify those with 'DONT_REQ_PREAUTH' flag, with progress indicator
            $allUsers = Get-ADUser -Filter * -Properties samaccountname, userprincipalname, useraccountcontrol
            $total    = $allUsers.Count
            $counter  = 0
            $results  = @()
            foreach ($user in $allUsers) {
                $counter++
                Write-Progress -Activity "Finding AS-REP roastable users" -Status "Scanning $counter of $total accounts..." -PercentComplete ($counter / $total * 100)
                # DONT_REQUIRE_PREAUTH flag (0x00400000 or 4194304) - include users where this bit is set
                if ($user.UserAccountControl -band 4194304) {
                    $results += [PSCustomObject]@{
                        SamAccountName    = $user.SamAccountName
                        UserPrincipalName = $user.UserPrincipalName
                    }
                }
            }
            Write-Progress -Activity "Finding AS-REP roastable users" -Completed
            $results
            Prompt-Export -BaseName $baseName -Data $results
        }
        "3" {
            # Option 3: Find Kerberoastable users (accounts with an SPN set)
            $baseName = "KerberoastableUsers"
            # Retrieve all users and identify those with Service Principal Names, with progress indicator
            $allUsers = Get-ADUser -Filter * -Properties samaccountname, serviceprincipalname
            $total    = $allUsers.Count
            $counter  = 0
            $results  = @()
            foreach ($user in $allUsers) {
                $counter++
                Write-Progress -Activity "Finding Kerberoastable users" -Status "Scanning $counter of $total accounts..." -PercentComplete ($counter / $total * 100)
                # Include users that have any ServicePrincipalName (SPN) defined
                if ($user.ServicePrincipalName) {
                    # Join multiple SPN values into a single string if present
                    $spnList = $user.ServicePrincipalName -join "; "
                    $results += [PSCustomObject]@{
                        SamAccountName       = $user.SamAccountName
                        ServicePrincipalName = $spnList
                    }
                }
            }
            Write-Progress -Activity "Finding Kerberoastable users" -Completed
            $results
            Prompt-Export -BaseName $baseName -Data $results
        }
        "4" {
            # Option 4: List disabled user accounts
            $baseName = "DisabledAccounts"
            # Retrieve all users and identify disabled accounts, with progress indicator
            $allUsers = Get-ADUser -Filter * -Properties samaccountname, useraccountcontrol
            $total    = $allUsers.Count
            $counter  = 0
            $results  = @()
            foreach ($user in $allUsers) {
                $counter++
                Write-Progress -Activity "Finding disabled accounts" -Status "Scanning $counter of $total users..." -PercentComplete ($counter / $total * 100)
                # ACCOUNTDISABLE flag (0x0002) - include users where this bit is set
                if ($user.UserAccountControl -band 2) {
                    $results += [PSCustomObject]@{ SamAccountName = $user.SamAccountName }
                }
            }
            Write-Progress -Activity "Finding disabled accounts" -Completed
            $results
            Prompt-Export -BaseName $baseName -Data $results
        }
        "5" {
            # Option 5: List user accounts with passwords that never expire
            $baseName = "PasswordNeverExpires"
            # Retrieve all users and identify accounts with 'password never expires', with progress indicator
            $allUsers = Get-ADUser -Filter * -Properties samaccountname, useraccountcontrol
            $total    = $allUsers.Count
            $counter  = 0
            $results  = @()
            foreach ($user in $allUsers) {
                $counter++
                Write-Progress -Activity "Finding 'password never expires' accounts" -Status "Scanning $counter of $total users..." -PercentComplete ($counter / $total * 100)
                # PASSWD_NEVER_EXPIRES flag (0x10000 or 65536) - include users where this bit is set
                if ($user.UserAccountControl -band 65536) {
                    $results += [PSCustomObject]@{ SamAccountName = $user.SamAccountName }
                }
            }
            Write-Progress -Activity "Finding 'password never expires' accounts" -Completed
            $results
            Prompt-Export -BaseName $baseName -Data $results
        }
        "6" {
            # Option 6: List user accounts that do not require a password
            $baseName = "PasswordNotRequired"
            # Retrieve all users and identify accounts with 'password not required', with progress indicator
            $allUsers = Get-ADUser -Filter * -Properties samaccountname, useraccountcontrol
            $total    = $allUsers.Count
            $counter  = 0
            $results  = @()
            foreach ($user in $allUsers) {
                $counter++
                Write-Progress -Activity "Finding 'password not required' accounts" -Status "Scanning $counter of $total users..." -PercentComplete ($counter / $total * 100)
                # PASSWD_NOTREQD flag (0x20 or 32) - include users where this bit is set
                if ($user.UserAccountControl -band 32) {
                    $results += [PSCustomObject]@{ SamAccountName = $user.SamAccountName }
                }
            }
            Write-Progress -Activity "Finding 'password not required' accounts" -Completed
            $results
            Prompt-Export -BaseName $baseName -Data $results
        }
        "7" {
            # Option 7: List user accounts that are currently locked out
            $baseName = "LockedOutAccounts"
            # Retrieve all users and identify accounts that are locked out, with progress indicator
            $allUsers = Get-ADUser -Filter * -Properties samaccountname, useraccountcontrol
            $total    = $allUsers.Count
            $counter  = 0
            $results  = @()
            foreach ($user in $allUsers) {
                $counter++
                Write-Progress -Activity "Finding locked out accounts" -Status "Scanning $counter of $total users..." -PercentComplete ($counter / $total * 100)
                # LOCKOUT flag (0x10 or 16) - include users where this bit is set
                if ($user.UserAccountControl -band 16) {
                    $results += [PSCustomObject]@{ SamAccountName = $user.SamAccountName }
                }
            }
            Write-Progress -Activity "Finding locked out accounts" -Completed
            $results
            Prompt-Export -BaseName $baseName -Data $results
        }
        "8" {
            # Option 8: List members of the Domain Admins group (recursively)
            $baseName = "DomainAdminsMembers"
            # Retrieve all members (users and groups) of 'Domain Admins' and show progress
            $members = Get-ADGroupMember -Identity "Domain Admins" -Recursive
            $total   = $members.Count
            $counter = 0
            $results = @()
            foreach ($member in $members) {
                $counter++
                Write-Progress -Activity "Listing Domain Admins members" -Status "Processing $counter of $total members..." -PercentComplete ($counter / $total * 100)
                # Determine object type and get SamAccountName accordingly
                if ($member.objectClass -eq 'user') {
                    $obj = Get-ADUser -Identity $member.DistinguishedName -Properties SamAccountName
                }
                elseif ($member.objectClass -eq 'group') {
                    $obj = Get-ADGroup -Identity $member.DistinguishedName -Properties SamAccountName
                }
                else {
                    $obj = $null
                }
                if ($obj) {
                    $results += [PSCustomObject]@{ SamAccountName = $obj.SamAccountName }
                }
            }
            Write-Progress -Activity "Listing Domain Admins members" -Completed
            $results
            Prompt-Export -BaseName $baseName -Data $results
        }
        "9" {
            # Option 9: List all groups with their category and scope
            $baseName = "AllGroups"
            # Retrieve all groups and show progress
            $allGroups = Get-ADGroup -Filter * -Properties GroupCategory, GroupScope
            $total     = $allGroups.Count
            $counter   = 0
            $results   = @()
            foreach ($group in $allGroups) {
                $counter++
                Write-Progress -Activity "Listing all groups" -Status "Processing $counter of $total groups..." -PercentComplete ($counter / $total * 100)
                $results += [PSCustomObject]@{
                    Name          = $group.Name
                    GroupCategory = $group.GroupCategory
                    GroupScope    = $group.GroupScope
                }
            }
            Write-Progress -Activity "Listing all groups" -Completed
            $results
            Prompt-Export -BaseName $baseName -Data $results
        }
        "10" {
            # Option 10: List all computers with their DNS hostname and OS
            $baseName = "AllComputers"
            # Retrieve all computers and show progress
            $allComputers = Get-ADComputer -Filter * -Properties DNSHostName, OperatingSystem
            $total        = $allComputers.Count
            $counter      = 0
            $results      = @()
            foreach ($comp in $allComputers) {
                $counter++
                Write-Progress -Activity "Listing all computers" -Status "Processing $counter of $total computers..." -PercentComplete ($counter / $total * 100)
                $results += [PSCustomObject]@{
                    Name            = $comp.Name
                    DNSHostName     = $comp.DNSHostName
                    OperatingSystem = $comp.OperatingSystem
                }
            }
            Write-Progress -Activity "Listing all computers" -Completed
            $results
            Prompt-Export -BaseName $baseName -Data $results
        }
        "11" {
            # Option 11: List users that have the Description field set
            $baseName = "UsersWithDescription"
            # Retrieve all users and find those with a description, with progress indicator
            $allUsers = Get-ADUser -Filter * -Properties description, samaccountname
            $total    = $allUsers.Count
            $counter  = 0
            $results  = @()
            foreach ($user in $allUsers) {
                $counter++
                Write-Progress -Activity "Finding users with description" -Status "Scanning $counter of $total users..." -PercentComplete ($counter / $total * 100)
                if ($user.Description -ne $null) {
                    $results += [PSCustomObject]@{
                        SamAccountName = $user.SamAccountName
                        Description    = $user.Description
                    }
                }
            }
            Write-Progress -Activity "Finding users with description" -Completed
            $results
            Prompt-Export -BaseName $baseName -Data $results
        }
        "12" {
            # Option 12: List all Organisational Units (OUs)
            $baseName = "OrganizationalUnits"
            # Retrieve all OUs and show progress
            $allOUs  = Get-ADOrganizationalUnit -Filter * -Properties *
            $total   = $allOUs.Count
            $counter = 0
            foreach ($ou in $allOUs) {
                $counter++
                Write-Progress -Activity "Listing all OUs" -Status "Processing $counter of $total OUs..." -PercentComplete ($counter / $total * 100)
                # No transformation needed; we will output full OU objects
            }
            Write-Progress -Activity "Listing all OUs" -Completed
            $results = $allOUs
            $results
            Prompt-Export -BaseName $baseName -Data $results
        }
        "13" {
            # Option 13: List all domain trusts
            $baseName = "DomainTrusts"
            $results  = Get-ADTrust -Filter *
            $results
            Prompt-Export -BaseName $baseName -Data $results
        }
        "14" {
            # Option 14: List all forest trusts for the current forest
            $baseName = "ForestTrusts"
            $results  = (Get-ADForest).Trusts
            $results
            Prompt-Export -BaseName $baseName -Data $results
        }
        "15" {
            # Option 15: List all Group Policies (GPOs) with details
            $baseName = "GroupPolicies"
            $results  = Get-GPO -All | Select-Object DisplayName, Id, CreationTime, ModificationTime
            $results
            Prompt-Export -BaseName $baseName -Data $results
        }
        "16" {
            # Option 16: Exit the script
            Write-Host "Exiting..." -ForegroundColor Yellow
            exit  # Terminate the script
        }
        default {
            # Handle invalid menu selections
            Write-Host "Invalid choice, please try again." -ForegroundColor Red
        }
    }
}

# Main loop: show the menu and process user input until exit is selected
do {
    Show-Menu
    $choice = Read-Host "Select an option (1-16)"
    Run-Query $choice
} while ($true)
