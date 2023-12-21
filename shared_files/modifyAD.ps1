
# Global array Passwords for bad pw's for users
$Global:Passwords = @("Password", "123456", "123456789", "12345678", "12345", "1234567", "qwerty", "abc123", "111111", "123123",
    "admin", "letmein", "welcome", "monkey", "password1", "1234", "sunshine", "123321", "1234567890", "princess",
    "football", "baseball", "iloveyou", "password123", "1234567891", "1234567892", "1234567893", "1234567894",
    "1234567895", "1234567896", "1234567897", "1234567898", "1234567899", "12345678910", "12345678911", "qwerty123",
    "passw0rd", "admin123", "letmein123", "welcome123", "monkey123", "123456abc", "football123", "baseball123",
    "iloveyou123", "password!@#", "1234abcd", "sunshine123", "123123abc", "123abc456", "password1234", "qwertyuiop",
    "asdfghjkl", "zxcvbnm", "987654321", "superman", "batman", "trustno1", "login", "master", "123abc", "555555",
    "7777777", "8888888", "9999999", "0000000", "testing123", "letmeout", "letmein!", "welcome1234", "monkey321",
    "passw0rd123", "123abc!", "iloveyou!", "football!", "baseball!", "sunshine!", "admin!", "qwerty123!", "password1!",
    "letmein1", "welcome1", "monkey1", "1234!", "!@#$%^&", "qwerty1234", "asdfghjkl123", "zxcvbnm123", "9876543210",
    "superman123", "batman123", "trustno1!", "login123", "master123", "123abc!", "555555!", "7777777!", "8888888!",
    "9999999!", "0000000!");
# Global array Groups for group creation
# Global array for ACL object permissions and types to exploit
$Global:ACL = @('GenericAll','GenericWrite','WriteOwner','WriteDACL','AllExtendedRights','ForceChangePassword','Self','WriteProperty');  
# Global array for service account info for Kerberos
$Global:ServicesAccountsAndSPNs = @('mssql_svc,mssqlserver','http_svc,httpserver','exchange_svc,exserver');
# Below 2 arrays are empty to create users and groups and fill them
$Global:CreatedUsers = @();
$Global:GroupObjects = @();
# Will initiliaze to the domain entered upon call of script
$Global:Domain = "";
$Global:InfoRead = "`t[>]"
function GoodOutput { param( $String ) Write-Host $Global:InfoRead  $String -ForegroundColor 'Green'}
function BadOutput  { param( $String ) Write-Host $Global:InfoRead $String -ForegroundColor 'Red'  }
function InfoOutput { param( $String ) Write-Host $Global:InfoRead $String -ForegroundColor 'Cyan' }

# Parameter $InputList expects array
# Element is returned as output after generating random numbers and selecting elements from array
# Overall, pass array as argument, return random elements from that array
function AD-RandomInput {
    Param(
      [array]$InputList
    )
    return Get-Random -InputObject $InputList
}

# Create AD Groups and assign users to those groups
# Param as array input for GroupList and iterates over each in GroupList
# InfoOutput is aesthetic only
# Try block creates new groups with global scope, errors ignored in Catch
# For loop adds users to the group not to exceed 20
# Group name added to Group Objects array
# function AddADGroup {
#     Param(
#         [array]$GroupList
#     )
#     foreach ($group in $GroupList) {
#         InfoOutput "Creating Group by name of: $group"
#         Try { New-ADGroup -name $group -GroupScope Global } Catch {}
#         for ($i=1; $i -le (Get-Random -Maximum 20); $i=$i+1 ) {
#             $newuser = (AD-RandomInput -InputList $Global:CreatedUsers)
#             InfoOutput "Adding $randomuser to: $group"
#             Try { Add-ADGroupMember -Identity $group -Members $newuser } Catch {}
#         }
#         $Global:GroupObjects += $group;
#     }
# }

# Param creates 5 users if not specified. System web used to generate secure pw
# Helps generate multiple user accounts with pw's added to SAM and Principal
# Try block there to catch errors during New-ADUser creation
# function AddADUser {
#     Param(
#         [int]$limit = 5
#     )
#     Add-Type -AssemblyName System.Web
#     for ($i=1; $i -le $limit; $i=$i+1 ) {
#         $firstname = (AD-RandomInput -InputList $Global:Names);
#         $lastname = (AD-RandomInput -InputList $Global:Names);
#         #$fullname = "{0} {1}" -f ($firstname , $lastname);
#         $SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower() 
#         #("{0}.{1}" -f ($firstname, $lastname)).ToLower();
#         $principalname = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
#         #"{0}.{1}" -f ($firstname, $lastname);
#         $generated_password = ([System.Web.Security.Membership]::GeneratePassword(12,2))
#         InfoOutput "Creating $SamAccountName User"
#         Try { New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $generated_password -AsPlainText -Force) -PassThru | Enable-ADAccount } Catch {}
#         $Global:CreatedUsers += $SamAccountName;
#     }
# }

# function RemoveADGroup {
#     Param(
#         [array]$GroupList
#     )
#     foreach ($group in $GroupList) {
#         InfoOutput "Removing Group: $group"
#         Try {
#             Remove-ADGroup -Identity $group -Confirm:$false
#         } Catch {}
#         $Global:GroupObjects -= $group
#     }
# }
# function RemoveADUser {
#     Param(
#         [array]$UserList
#     )
#     foreach ($user in $UserList) {
#         InfoOutput "Removing User: $user"
#         Try {
#             Remove-ADUser -Identity $user -Confirm:$false
#         } Catch {}
#         $Global:CreatedUsers -= $user
#     }
# }

# Adds Access Control Entry to security descriptor
# Allows modifying of Access Control permissions
# cmdletbinding grants us features for param validation
# Dst specifies LDAP path of dst object
# Source identifies entity 
# Rights denote permissions granted through identity on object
# ADObject represents DST plus ADSI to query AD and modify
# ACE allows access by default through $type
# Access Rule created for ACE then added to descriptor
function AddACL {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Destination,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Security.Principal.IdentityReference]$Source,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Rights

    )
    $ADObject = [ADSI]("LDAP://" + $Destination)
    $identity = $Source
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
    $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
    $ADObject.psbase.commitchanges()
}

# Selects random account and SPN from global. Then split to svc and spn
# Random pw generated from global and assigned
# Aesthetic output
# Inside Try, AD svc account created with svc and spn name
# Pw set securely using securestring
# Account localized  via Restrict
# After creation, iteration through global using foreach on each diff svc acct
# Split svc and spn and assign, generate new pw 
# Inside nested Try, new AD svc created and not restricted
# Simulates creation of vulnerable accounts in AD. Creates one svc acct for an spn
# Randomly generates pw's. Purpose is essentially to create situation where svc is susceptible to 
# Kerberoasting, and extract encrypted TGS ticket for offline cracking
function Kerberoasting {
    $selected_service = (AD-RandomInput -InputList $Global:ServicesAccountsAndSPNs)
    $svc = $selected_service.split(',')[0];
    $spn = $selected_service.split(',')[1];
    $password = AD-RandomInput -InputList $Global:Passwords;
    InfoOutput "Kerberoasting $svc $spn"
    Try { New-ADServiceAccount -Name $svc -ServicePrincipalNames "$svc/$spn.$Global:Domain" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -RestrictToSingleComputer -PassThru } Catch {}
    foreach ($sv in $Global:ServicesAccountsAndSPNs) {
        if ($selected_service -ne $sv) {
            $svc = $sv.split(',')[0];
            $spn = $sv.split(',')[1];
            InfoOutput "Creating $svc services account"
            $password = ([System.Web.Security.Membership]::GeneratePassword(12,2))
            Try { New-ADServiceAccount -Name $svc -ServicePrincipalNames "$svc/$spn.$Global:Domain" -RestrictToSingleComputer -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru } Catch {}

        }
    }
}

# For loop iterates randomly 6x
# Inside the loop; random user acct selected and assigned to randomuser
# Same for random password, which is then set to user
# Reset calls for pw reset and new pw is secured
# Control modifies acct control of user and disables pre-authN
# This targets Kerberos AS and TGS tickets for users without needing to present TGT
# Ultimately extracting tickets offline for cracking
function ASREPRoasting {
  # Get all users in the domain
  $users = Get-ADUser -Filter *

  foreach ($user in $users) {
      for ($i=1; $i -le (Get-Random -Maximum 10); $i=$i+1 ) {
          $password = AD-RandomInput -InputList $Global:Passwords;
          Set-AdAccountPassword -Identity $user.SamAccountName -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
          Set-ADAccountControl -Identity $user.SamAccountName -DoesNotRequirePreAuth 1
          InfoOutput "AS-REPRoasting $($user.SamAccountName)"
      }
  }
}

# For loop iterates randomly 6x
# Inside loop, random user selected and assigned
# Random pw generated up to 12 characters including 2 non-alpha
# Resets account pw and sets secure string
# Set-ADUser adds description info for user after Description
function PwdInDescription {
  # Get all users in the domain
  $users = Get-ADUser -Filter *

  foreach ($user in $users) {
      for ($i=1; $i -le (Get-Random -Maximum 6); $i=$i+1 ) {
          $password = ([System.Web.Security.Membership]::GeneratePassword(12,2))
          Set-AdAccountPassword -Identity $user.SamAccountName -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
          Set-ADUser $user.SamAccountName -Description "User Password $password"
          InfoOutput "Password in Description : $($user.SamAccountName)"
      }
  }
}

# User accounts in AD have default pw set
# For loop iterates 5x, selecting random user and assigning 
# Default pw is assigned
# Cmdlet resets pw and sets as secure string
# Set-ADUser sets user description in field
# Set-AdUser sets user to require password change on login
function DefaultPassword {
  # Get all users in the domain
  $users = Get-ADUser -Filter *

  foreach ($user in $users) {
      for ($i=1; $i -le (Get-Random -Maximum 5); $i=$i+1 ) {
          $password = "Changeme123!";
          Set-AdAccountPassword -Identity $user.SamAccountName -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
          Set-ADUser $user.SamAccountName -Description "New User ,DefaultPassword"
          Set-AdUser $user.SamAccountName -ChangePasswordAtLogon $true
          InfoOutput "Default Password : $($user.SamAccountName)"
      }
  }
}

# Write to Windows\Tasks as it's the "tmp" of Linux
function WeakenPwdPolicy {
    secedit /export /cfg C:\Windows\Tasks\secpol.cfg
    (Get-Content C:\Windows\Tasks\secpol.cfg).replace("PasswordComplexity = 1", "PasswordComplexity = 0").replace("MinimumPasswordLength = 7", "MinimumPasswordLength = 1") | Out-File C:\Windows\Tasks\secpol.cfg
    secedit /configure /db c:\windows\security\local.sdb /cfg C:\Windows\Tasks\secpol.cfg /areas SECURITYPOLICY
    Remove-Item -Path C:\Windows\Tasks\secpol.cfg -Force -Confirm:$false
}
# Supply a strengthen policy for Undo
function StrengthenPwdPolicy{
    secedit /export /cfg C:\Windows\Tasks\secpol.cfg
    (Get-Content C:\Windows\Tasks\secpol.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1").replace("MinimumPasswordLength = 1", "MinimumPasswordLength = 7") | Out-File C:\Windows\Tasks\secpol.cfg
    secedit /configure /db c:\windows\security\local.sdb /cfg C:\Windows\Tasks\secpol.cfg /areas SECURITYPOLICY
    Remove-Item -force C:\Windows\Tasks\secpol.cfg -confirm:$false
}

# Don't forget you'll need to import the modules
# Import-Module ./ChatGPTFinal.ps1
# Then run Invoke-AD -UsersLimit # -DomainName "skillcloud.local" 
# Additionally, we're attempting to add another parameter for outputting
#   user information to a json file of the users choice
function Invoke-AD {
    Param(
        [int]$UsersLimit = 30,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainName,
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $OutputFileName
    )
    $Global:Domain = $DomainName
    Set-ADDefaultDomainPasswordPolicy -Identity $Global:Domain -LockoutDuration 00:01:00 -LockoutObservationWindow 00:01:00 -ComplexityEnabled $false -ReversibleEncryptionEnabled $False -MinPasswordLength 4
    AddADUser -limit $UsersLimit
    GoodOutput "Users Created"
    AddADGroup -GroupList $Global:Groups
    GoodOutput "$Global:Groups"
    Kerberoasting
    GoodOutput "Kerberoasting Complete"
    ASREPRoasting
    GoodOutput "AS-REPRoasting Complete"
    PwdInDescription
    GoodOutput "Password In Description Complete"
    DefaultPassword
    GoodOutput "Default Password Complete"
    WeakenPwdPolicy
    GoodOutput "Password Policy Weakend"

    if ($OutputFileName) {
        $usersData = foreach ($user in $Global:CreatedUsers) {
            $userObj = Get-ADUser -Identity $user -Properties GivenName, Surname, MemberOf
            [PSCustomObject]@{
                "UserName" = $userObj.SamAccountName
                "FullName" = "$($userObj.GivenName) $($userObj.Surname)"
                "Groups" = $userObj.MemberOf
            }
        }
        $outputData = @{
            "Users" = $usersData
            "Groups" = $Global:GroupObjects
        }
        $outputData | ConvertTo-Json | Out-File -FilePath $OutputFileName -Encoding UTF8
        GoodOutput "Output JSON file created: $OutputFileName"
    }
    
}

# Undo functionality to revert actions performed
# Undo-AD -DomainName "skillcloud.local"
# function Undo-AD {
#     Param(
#         [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
#         [ValidateNotNullOrEmpty()]
#         [System.String]
#         $DomainName
#     )
#     $Global:Domain = $DomainName

#     # Revert the actions performed in the Invoke-AD function
#     RemoveADGroup -Identity $Global:Groups -Confirm:$false
#     RemoveADUser -Identity $Global:CreatedUsers -Confirm:$false
#     StrengthenPwdPolicy

#     GoodOutput "Undo complete"
# }