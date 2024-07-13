# Make easier to debug. Variables must be declared which guards against typos.
Set-StrictMode -Version latest
$ErrorActionPreference = "Stop"

# Why not....
$Banner=@'
Active Directory
  _____ _                        __     _             
 |_   _(_) ___ _ __ ___    ___  / _|   (_) ___  _   _ 
   | | | |/ _ \ '__/ __|  / _ \| |_    | |/ _ \| | | |
   | | | |  __/ |  \__ \ | (_) |  _|   | | (_) | |_| |
   |_| |_|\___|_|  |___/  \___/|_|    _/ |\___/ \__, |
                                     |__/       |___/ 
                Yet another Tiered Admin Model script...
                https://github.com/alexmags/ADTiersOfJoy
'@
write-output $banner

# Credits
    # Credit to joegasper @ https://gist.github.com/joegasper/3fafa5750261d96d5e6edf112414ae18
    # Credit to przybylskirobert @ https://github.com/przybylskirobert/ADSecurity/blob/master/Tiering/Scripts/Set-OUUserPermissions.ps1
    # Credit to SalutAToi @ https://github.com/SalutAToi/AD-Tier-Administration/blob/master/ACESkel.json  Je vous remercie

# Depends on ActiveDirectory module from Windows Server Remote Server Admin Tools (RSAT)
Import-Module ActiveDirectory  # assumes remote server admin tools RSAT installed

# Assuming you're signed into AD domain, OUs will be relative to this domain
$domainDN="$((get-addomain).DistinguishedName)" 
$rootOU='Corp'  # This will be top level OU.  It's generic to survive company rename/rebranding. Leaves space for parallel OUs for company mergers/aquisitions/divestitures.

<# Define tiered admin model OUs, groups and group nesting and OU ACLs. This could be a separte data file.
    
    This Tiered Admin Stucture is just an example. Remix to your own requirements based on how you manage AD Group Policy and delegate access.
    
    OU-     Makes an OU.  Remember to create parent OUs before child OUs.
    ACL-    Crrats Access Control List entries. Grants security group a set of permissions on current OU/last OU mentioned
    Group-  Make a security group in last OU mentioned
    AssignRolePermission-  Nests 2nd group (permissions) in 1st group (role)
    
    The code steps through the TAM structure top to bottom. So add lines in order you want them appied. Parent OUs first. Create groups before try to nest groups.
#>

$TAMStructure=@'
OU-#ROOT#\Tier 0,Tier zero zone
OU-#ROOT#\Tier 0\Computers,T0 servers
ACL-PermADT0ComputersOU,CreateDeleteManageComputerObjects,Domain join and manage T0 servers
OU-#ROOT#\Tier 0\Computers\Identity
OU-#ROOT#\Tier 0\Computers\PKI
OU-#ROOT#\Tier 0\Computers\PAW,Priviliged Access Workstations and jumpboxes for T0 admins
OU-#ROOT#\Tier 0\Groups
ACL-PermADT0GroupsOU,CreateDeleteManageGroupObjects,Delegate access to manage T0 groups
OU-#ROOT#\Tier 0\Groups\Permission Groups,These groups grant access
Group-PermADT0ComputersOU,Members can manage objects in T0 computer OUs
Group-PermADT0ComputersGPOs,Members can manage OUs linked to T0 computers OU
Group-PermADT0ComputerLocalAdmin,Members are local admins on T0 machines
Group-PermADT0ComputerServerOperator,Members are server operators on T0 machines
Group-PermADT0GroupsOU,Members can manage T0 security groups
Group-PermADT0AccountsOU,Members can manage T0 accounts
Group-PermADT0AdminsOU,Members can manage T0 admin accounts
Group-PermADT1ComputersOU,Members can manage T1 computer OUs
Group-PermADT1ComputersGPOs,Members can manage GPOs linked to T1 OUs
Group-PermADT1ComputersLocalAdmin,Members are local admin on T1 computers
Group-PermADT1GroupsOU,Members can manage T1 security groups
Group-PermADT1AccountsOU,Members can manage T1 accounts
Group-PermADT1AdminsOU,Managers can manage T1 admins
Group-PermADT2ComputersOU,Members can manage object in T2 computer OUs
Group-PermADT2ComputersGPOs,Members can manage GPOs linked to T2 OUs
Group-PermADT2ComputersLocalAdmin,Members are local admin on T2 computers
Group-PermADT2GroupsOU,Members can manage T2 security groups
Group-PermADT2AdminsOU,Members can manage T2 admin accounts
Group-PermADT2AccountsOU,Members can manage T2 accounts
Group-TempPermADT2Accounts,Members can temporarily manage T2 accounts until group emptied nightly
OU-#ROOT#\Tier 0\Groups\Permission Groups\Time Based Access,These groups are automatically emptied
Group-TempPermDomainAdmins,Members are temporarily domain admin until group emptied every night
OU-#ROOT#\Tier 0\Groups\Role Groups,These groups describe job roles and task. Roles give one or more permission groups. T0 accounts/computers only
Group-RoleT0InfraAdmins,Infra team ADM accounts
AssignRolePermission-RoleT0InfraAdmins,PermADT0ComputersOU
AssignRolePermission-RoleT0InfraAdmins,PermADT0AccountsOU
AssignRolePermission-RoleT0InfraAdmins,PermADT0groupsOU
AssignRolePermission-RoleT0InfraAdmins,PermADT1ComputersOU
AssignRolePermission-RoleT0InfraAdmins,PermADT1AccountsOU
AssignRolePermission-RoleT0InfraAdmins,PermADT1AdminsOU
AssignRolePermission-RoleT0InfraAdmins,PermADT1groupsOU
AssignRolePermission-RoleT0InfraAdmins,PermADT2ComputersOU
AssignRolePermission-RoleT0InfraAdmins,PermADT2AccountsOU
AssignRolePermission-RoleT0InfraAdmins,PermADT2AdminsOU
AssignRolePermission-RoleT0InfraAdmins,PermADT2groupsOU
AssignRolePermission-RoleT0SavyintConnectors,Pre-Windows 2000 Compatible Access
AssignRolePermission-RoleT0SavyintConnectors,PermADT0AccountsOU
AssignRolePermission-RoleT0SavyintConnectors,PermADT0groupsOU
AssignRolePermission-RoleT0SavyintConnectors,PermADT1AccountsOU
AssignRolePermission-RoleT0SavyintConnectors,PermADT1AdminsOU
AssignRolePermission-RoleT0SavyintConnectors,PermADT1groupsOU
AssignRolePermission-RoleT0SavyintConnectors,PermADT2AccountsOU
AssignRolePermission-RoleT0SavyintConnectors,PermADT2AdminsOU
AssignRolePermission-RoleT0SavyintConnectors,PermADT2groupsOU
OU-#ROOT#\Tier 0\Entra Managed,Cloud objects managed in Entra ID
OU-#ROOT#\Tier 0\Admins,T0 admininistrators inc _da accounts
ACL-PermADT0AdminsOU,CreateDeleteManageUserObjects,Delegate create and change access to user objects
OU-#ROOT#\Tier 0\Accounts,user and service accounts for sign-in to T0 resources. Managed by T0 admins
ACL-PermADT0AccountsOU,CreateDeleteManageUserObjects,Delegate create and change access to user objects
OU-#ROOT#\Tier 0\Accounts\Test Accounts
OU-#ROOT#\Tier 0\Accounts\Service Accounts
OU-#ROOT#\Tier 0\Accounts\Shared Accounts
OU-#ROOT#\Tier 0\Accounts\Terminated
OU-#ROOT#\Tier 1,Tier one zone
OU-#ROOT#\Tier 1\Computers,Application servers
ACL-PermADT1ComputersOU,CreateDeleteManageComputerObjects,Domain join and manage computer objects
OU-#ROOT#\Tier 1\Computers\PAW,Priv Access Workstations used by T1 admins
OU-#ROOT#\Tier 1\Groups
ACL-PermADT1GroupsOU,CreateDeleteManageGroupObjects,Delegate create and change access to groups
OU-#ROOT#\Tier 1\Groups\Permission Groups,t0,t1 accounts/roles/computers onlt
Group-PermADT2ComputersLocalAdmin,Members are local admin on T2 computers
Group-PermApp1Admins,Members are admins on app 1
Group-PermApp2Admins,Members are admins on app 2
Group-PermApp1DB_SYSAdmin,Members are DBAs on App1
Group-PermSaaS1Admins,Members are SaaS app 1 admins
Group-PermSaaS2Admins,Members are SaaS app 2 admins
Group-PermFilesChocoRepoT1_RO,\\dfs path here
Group-PermFilesChocoRepoT1_RW,\\dfs path here
Group-PermFilesDeptC,\\dfs path here
OU-#ROOT#\Tier 1\Groups\Permission Groups\Time Based Access,These groups are automatically emptied
OU-#ROOT#\Tier 1\Groups\Role Groups,These groups describe job roles and task. Roles give one or more permission groups. T0 and T1 accounts/computers only
Group-RoleT1AdminInfoSecApps,Infosec team admin accounts for permissions in infosec apps
Group-RoleT1AdminBusinessApps,Business apps team admin accounts for permissions in business apps
Group-RoleT1ITServerSupportAdmins,Server support team admin accounts for permissions to infra services
Group-RoleT1DomainJoiners,Automation accounts that add computers to domain at T1 level and below (MDT and VDI)
AssignRolePermission-RoleT1BAUAdmins,PermADT1ComputersOU
AssignRolePermission-RoleT1BAUAdmins,PermADT1AccountsOU
AssignRolePermission-RoleT1BAUAdmins,PermADT1AdminsOU
AssignRolePermission-RoleT1BAUAdmins,PermADT1groupsOU
AssignRolePermission-RoleT1BAUAdmins,PermADT2ComputersOU
AssignRolePermission-RoleT1BAUAdmins,PermADT2AccountsOU
AssignRolePermission-RoleT1BAUAdmins,PermADT2AdminsOU
AssignRolePermission-RoleT1BAUAdmins,PermADT2groupsOU
AssignRolePermission-RoleT1BAUAdmins,PermFilesChocoRepoT1_RW
AssignRolePermission-Domain Users,PermFilesChocoRepoT1_RO
AssignRolePermission-Domain Computers,PermFilesChocoRepoT1_RO
AssignRolePermission-RoleT1DomainJoiners,PermADT1ComputersOU
AssignRolePermission-RoleT1DomainJoiners,PermADT2ComputersOU
AssignRolePermission-RoleT1AdminBusinessApps,PermSaaS1Admins
AssignRolePermission-RoleT1AdminBusinessApps,PermSaaS2Admins
AssignRolePermission-RoleT1AdminBusinessApps,PermApp1Admins
AssignRolePermission-RoleT1AdminBusinessApps,PermApp2Admins
OU-#ROOT#\Tier 1\Admins,T1 ADM accounts. Blocked from sign-in to T2 desktops. Deny login interactive policy
ACL-PermADT1AdminsOU,CreateDeleteManageUserObjects,Delegate create and change access to user objects
OU-#ROOT#\Tier 1\Accounts,user and service accounts for sign-in to T1 resources. Managed by T1 admins
ACL-PermADT1AccountsOU,CreateDeleteManageUserObjects,Delegate create and change access to user objects
OU-#ROOT#\Tier 1\Accounts\Test Accounts
OU-#ROOT#\Tier 1\Accounts\Shared Accounts
OU-#ROOT#\Tier 1\Accounts\Service accounts,These account blocked for interactive sign-in. Deny login interactive policy
OU-#ROOT#\Tier 1\Accounts\Service accounts\SyncedToEntra
OU-#ROOT#\Tier 2,Tier two zone
OU-#ROOT#\Tier 2\Computers,User desktops
ACL-PermADT2ComputersOU,CreateDeleteManageComputerObjects,Domain join and managed computer objects
OU-#ROOT#\Tier 2\Computers\MultisessionHosts
OU-#ROOT#\Tier 2\Computers\Win10,Default location for new Win10 machines. Policy applied at this level
OU-#ROOT#\Tier 2\Computers\Win10\US,Regional settings locale
OU-#ROOT#\Tier 2\Computers\Win10\US\NewYork,Timezone and printers applied at this level
OU-#ROOT#\Tier 2\Computers\Win10\US\Miami
OU-#ROOT#\Tier 2\Computers\Win10\UK
OU-#ROOT#\Tier 2\Computers\Win10\UK\Northampton
OU-#ROOT#\Tier 2\Computers\Win10\UK\Luton
OU-#ROOT#\Tier 2\Computers\Win10\UK\Slough
OU-#ROOT#\Tier 2\Computers\Win10\FR
OU-#ROOT#\Tier 2\Computers\Win10\FR\LesGets
OU-#ROOT#\Tier 2\Computers\Win10\FR\Meribel
OU-#ROOT#\Tier 2\Computers\Win10\CH\Verbier
OU-#ROOT#\Tier 2\Computers\Win10\AT\Mooserwirt
OU-#ROOT#\Tier 2\Groups
ACL-PermADT2GroupsOU,CreateDeleteManageGroupObjects,Delegate create and change access to group objects
OU-#ROOT#\Tier 2\Groups\Permission Groups,These groups grant access to end user resources such as project shares
Group-PermFiles_ProjectA_RW,\\some dfs path
Group-PermFiles_ProjectB_RW,\\some dfs path
Group-PermFilesDeptC_RW,\\some dfs path
Group-PermFilesChocoRepoT2_RO,\\some dfs path
Group-PermFilesChocoRepoT2_RW,\\some dfs path
Group-PermSaas1,URL
Group-PermSaaS2,URL
Group-PermDesktopAppE,software package reference here
OU-#ROOT#\Tier 2\Groups\Permission Groups\Synced to Entra,User resources in Entra typically use Entra managed groups instead. AD T2 groups for AD authorised resources only
OU-#ROOT#\Tier 2\Groups\Permission Groups\Time Based Access,These groups are automatically emptied
OU-#ROOT#\Tier 2\Groups\Role Groups,These groups describe job roles and tasks. Roles give one or more permission groups. T2 accounts/computers only
Group-RoleHR,This role contains multiple permission groups for HR team
Group-RoleOperations,This role contains multiple permission groups for ops team
Group-RoleFinance,This role contains multiple permission groups for Finance team
Group-RoleStaff,This role contains multiple permission groups for all full time staff
Group-RoleContractors,This role contains multiple permission groups for contractors
Group-RoleInterns,This role contains multiple permission groups for interns
AssignRolePermission-RoleHR,PermFilesDeptC_RW
OU-#ROOT#\Tier 2\Admins
ACL-PermADT2AdminsOU,CreateDeleteManageUserObjects,Delegate create and change access to user objects
OU-#ROOT#\Tier 2\Accounts
ACL-PermADT2AccountsOU,CreateDeleteManageUserObjects,Delegate create and change access to user objects
OU-#ROOT#\Tier 2\Accounts\Service Accounts
OU-#ROOT#\Tier 2\Accounts\Test Accounts
OU-#ROOT#\Tier 2\Accounts\Shared Accounts
OU-#ROOT#\Tier 2\Accounts\Terminated
'@

# NUKE directory structure
#   VERY DANGEROUS!!!
#Get-ADOrganizationalUnit -SearchBase "OU=Corp,DC=rthsylab,DC=corp" -Filter * | Set-ADObject -ProtectedFromAccidentalDeletion:$false -PassThru
# dsrm -subtree -c "OU=Corp,DC=rthsylab,DC=corp" -noprompt

Function new-OUIfNotExist{
    param(
        [Parameter(Mandatory, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [string]$OUName,
        [Parameter(Mandatory, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [string]$OUPath,
        [string]$Description=$null
    )

    $newOU = "OU=$OUName,$OUPath"
    if (Get-ADOrganizationalUnit -SearchBase $OUPath -Filter "distinguishedName -eq '$newOU'") {
      return Get-ADOrganizationalUnit -SearchBase $OUPath -Filter "distinguishedName -eq '$newOU'"
    } else {
     
      if ($description) { return New-ADOrganizationalUnit -Name $ouName -Path $OUPath -Description $Description}
      else {return New-ADOrganizationalUnit -Name $ouName -Path $OUPath}
    }
}

# https://gist.github.com/joegasper/3fafa5750261d96d5e6edf112414ae18
function ConvertFrom-CanonicalOU {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [string]$CanonicalName
    )
    process {
        $obj = $CanonicalName.Split('\')
        [string]$DN = 'OU=' + $obj[$obj.count - 1]
        for ($i = $obj.count - 2; $i -ge 1; $i--) { $DN += ',OU=' + $obj[$i] }
        $obj[0].split('.') | ForEach-Object { $DN += ',DC=' + $_ }
        return $DN
    }
}

function new-GroupIfNotExist {
    param(
        [Parameter(Mandatory, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [string]$groupName,
        [Parameter(Mandatory, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [string]$OUPath,
        [string]$Description=$null
    )
    if(Get-ADGroup -filter {Name -eq $groupName} -ErrorAction Continue)
        {
            return Get-ADGroup -filter {Name -eq $groupName}
        } else
        {
            $ADGroup=New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security -Path $ouPath -Description $Description
            if ($description) {$ADGroup | set-adgroup -Description $Description}
            return $ADGroup
        }
}

function set-OUACL{
        param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$securityGroupName,
       
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OUPathDN,
       
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OUPermission
    )

   
    # Build lookup table for ACL GUIDs
    $rootdse = Get-ADRootDSE
    $domain = Get-ADDomain
    $guidmap = @{ }
    Get-ADObject -SearchBase ($rootdse.SchemaNamingContext) -LDAPFilter "(schemaidguid=*)" -Properties lDAPDisplayName, schemaIDGUID | ForEach-Object { $guidmap[$_.lDAPDisplayName] = [System.GUID]$_.schemaIDGUID }
    $extendedrightsmap = @{ }
    Get-ADObject -SearchBase ($rootdse.ConfigurationNamingContext) -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName, rightsGuid | ForEach-Object { $extendedrightsmap[$_.displayName] = [System.GUID]$_.rightsGuid }

     if(Get-ADGroup -filter {Name -eq $securityGroupName} -ErrorAction Continue)
    {
        #Write-Output "group found"

        $adGroup = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $securityGroupName).SID
        $SelfIdentifier = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-10"
        $acl = Get-ACL -Path "AD:$($OUPathDN)"
        Write-Host "Configuring User Permissions on $OUPathDN for group '$securityGroupName'" -ForegroundColor Green
        Write-Verbose 'Set-ACL -ACLObject $acl -Path ("AD:$($OUPathDN)")'
        Set-ACL -ACLObject $acl -Path ("AD:\$($OUPathDN)")
    switch ($OUPermission)
        {
                    # Delegate access to manage user objects in an OU
                    # 1 create/delete user objects at user OU level (new users)
                    # 2 Change/Write all user object properties (existing users) at user OU level
                    # 3 Permission to change user account password at user OU level
                    # 4 Permission to reset user account password at user OU level (this is a different and required permission compared to change password)
                    'CreateDeleteManageUserObjects' {

                        # 1 create/delete/move NEW user objects at user OU level
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "CreateChild, DeleteChild", "Allow", $guidmap["user"], "ALL"))
                       
                        # 2 Change/Write all user object properties (existing users)
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "ReadProperty", "Allow", "Descendents", $guidmap["user"]))
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "WriteProperty", "Allow", "Descendents", $guidmap["user"]))
                       
                        # 3 Permission to reset user account password at user OU level (this is a different and required permission compared to change password)
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "ExtendedRight", "Allow", $extendedrightsmap["Reset Password"], "Descendents", $guidmap["user"]))
                       
                        # 4 Permission to change user account password at user OU level
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "ExtendedRight", "Allow", $extendedrightsmap["Change Password"], "Descendents", $guidmap["user"]))
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "ReadProperty", "Allow", $guidmap["pwdLastSet"], "Descendents", $guidmap["user"]))
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "WriteProperty", "Allow", $guidmap["pwdLastSet"], "Descendents", $guidmap["user"]))

                        # 4 Permission to unlock user account password at user OU level
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "ReadProperty", "Allow", $guidmap["lockoutTime"], "Descendents", $guidmap["user"]))
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "WriteProperty", "Allow", $guidmap["lockoutTime"], "Descendents", $guidmap["user"]))


                        Set-ACL -path "AD:$($OUPathDN)" $acl -Verbose
                        }

                    'CreateDeleteManageComputerObjects'{
                        # Join domain
                        # Create and add these 4 rules for EVERY user or group you want to give these permissions.
                        # We are using the following overload for the constructor: https://msdn.microsoft.com/en-us/library/cawwkf0x(v=vs.110).aspx
                        # Note that no where in these rules, you are not referring to computer objects directly, but to properties of the computer objects.
                       
                        #  Creat/delete
                        #$ACL.AddAccessRule($RuleCreateAndDeleteComputer)
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "CreateChild,DeleteChild", "Allow", $guidmap["Computer"], "All"))

                        #  Read and write All Properties
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "ReadProperty, WriteProperty", "Allow", "Descendents", $guidmap["Computer"]))
                                                 
                        #  Read & write Permissions
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "ExtendedRight", "Allow", $extendedrightsmap["Account Restrictions"], "Descendents", $guidmap["Computer"]))
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "ReadProperty, WriteProperty", "Allow", $guidmap["userAccountControl"], "Descendents", $guidmap["Computer"]))
                         
                        #  Reset Password
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "ExtendedRight", "Allow", $extendedrightsmap["Reset Password"], "Descendents", $guidmap["Computer"]))
                         
                        #  Change Password
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "ExtendedRight", "Allow", $extendedrightsmap["Change Password"], "Descendents", $guidmap["Computer"]))

                        #  Machine account can Validate Write to DNS hostname  
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "ExtendedRight", "Allow", $extendedrightsmap['Validated write to DNS host name'], "Descendents", $guidmap["Computer"]))

       
                        #  Machine account can Validate Write to Service Principal Name (eg SQL install sets up SPNs for kerberos auth to SQL)
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "ExtendedRight", "Allow", $extendedrightsmap['Validated write to service principal name'], "Descendents", $guidmap["Computer"]))
       

                        # Machine account can update some of it's own attributes (set by gheto asset inventory WMI query to AD attribute shutdown script)
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SelfIdentifier, "ReadProperty, WriteProperty", "Allow", $guidmap["carLicense"], "Descendents", $guidmap["Computer"])) # abused to store LAN switch from cisco discovery protocol
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SelfIdentifier, "ReadProperty, WriteProperty", "Allow", $guidmap["serialNumber"], "Descendents", $guidmap["Computer"])) # # used to serial number from WMI
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SelfIdentifier, "ReadProperty, WriteProperty", "Allow", $guidmap["employeeType"], "Descendents", $guidmap["Computer"])) # abused to store manufacturer value from WMI
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SelfIdentifier, "ReadProperty, WriteProperty", "Allow", $guidmap["info"], "Descendents", $guidmap["Computer"])) # abused to store model value from WMI
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SelfIdentifier, "ReadProperty, WriteProperty", "Allow", $guidmap["carLicense"], "Descendents", $guidmap["Computer"])) # abused to store LAN switch from cisco discovery protocol
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SelfIdentifier, "ReadProperty, WriteProperty", "Allow", $guidmap["houseIdentifier"], "Descendents", $guidmap["Computer"])) # abused to store LAN switch port from cisco discovery protocol
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SelfIdentifier, "ReadProperty, WriteProperty", "Allow", $guidmap["roomNumber"], "Descendents", $guidmap["Computer"])) # abused to store LAN switch VLAN from cisco discovery protocol

                        Set-ACL -path "AD:$($OUPathDN)" $acl -Verbose

                    }

                    'CreateDeleteManageGroupObjects'{
                       
                        #  Create/delete groups
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "CreateChild,DeleteChild", "Allow", $guidmap["group"], "All"))

                        #  Read and write All Properties
                        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $adGroup, "ReadProperty, WriteProperty", "Allow", "Descendents", $guidmap["group"]))

                        Set-ACL -path "AD:$($OUPathDN)" $acl -Verbose

                    }
                    default {write-error "Undefined OU permission: $OUPermission"}
                }

        # report after change
        #(get-acl -Path "AD:$OUPathDN").access | Where-Object {$_.IdentityReference -ilike "*\$securityGroupName"}
    }
    else
    {
        Write-Warning "Failed to apply ACL until $securityGroupName exists"
}



# Process each line and make OUs and groups
$c1urrentOU=$null

new-OUIfNotExist -OUName $rootOU -OUPath "$((get-addomain).DistinguishedName)" | Out-Null
foreach ($TAMLine in $TAMStructure.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)){
    $currentOU=$null
    if ($TAMLine -like "#*"){ write-warning "Ignore $TAMLine" }
    if ($TAMLine -ilike "OU-*"){
        Write-Output $TAMLine
        $TAMLine=$TAMLine -replace "OU-",'' # trim header
        $TAMLine=$TAMLine -replace "#ROOT#","$((get-addomain).DNSRoot)\$rootOU" # Add local domain
        if ($TAMLine -like '*,*'){
            $OUDescription=$TAMLine.Split(',')[1]
            $TAMLine=$TAMLine.Split(',')[0]
        }
        else
        {
            $OUDescription=$null
        }
        Write-Output "`tOU $tamline"

        $ouPath=(ConvertFrom-CanonicalOU -CanonicalName (split-path $TAMLine.Trim() -Parent)) -replace "DC=#DOMAINNAME#","$((get-addomain).DistinguishedName)"
        $ouName=split-path $TAMLine -leaf
       
       
        #Write-Output "`tProcessing $ouName at $ouPath with $OUDescription"
        $currentOU=new-OUIfNotExist -OUName $ouName -OUPath $OUpath -Description $OUDescription
        #Write-Output "`tCompleted $ouName at $ouPath"
    }

    if ($TAMLine -ilike "Group-*"){
        $TAMLine=$TAMLine -replace "Group-",'' # trim header
        $currentOU=new-OUIfNotExist -OUName $ouName -OUPath $OUpath
        #New-ADGroup -Name $TAMLine -Path $currentOU -GroupScope Global -GroupCategory Security -ErrorAction SilentlyContinue
        #Write-Warning "New group $TAMLine at $currentOU"
        if ($TAMLine -like '*,*'){
            new-GroupIfNotExist -groupName $TAMLine.Split(',')[0] -OUPath $currentOU -Description $TAMLine.Split(',')[1] | Out-Null
            }
        else
        {
            new-GroupIfNotExist -groupName $TAMLine -OUPath $currentOU | out-null
            #if ($description) {$ADGroup | set-adgroup -Description $Description}
        }
    }
    # Set ACLs (skip if group doesn't exist yet)
    if ($TAMLine -ilike "ACL-*"){
        $TAMLine=$TAMLine -replace "ACL-",'' # trim header
        $GroupName=$TAMLine.Split(',')[0]
        $OUPermission=$TAMLine.Split(',')[1]
        $OUPermissionReason=$TAMLine.Split(',')[2]
        $currentOU=new-OUIfNotExist -OUName $ouName -OUPath $OUpath
        write-host "Group $GroupName getting permission $OUPermission on $($currentOU.DistinguishedName)"
        set-OUACL -securityGroupName $GroupName -OUPathDN $currentOU.DistinguishedName -OUPermission $OUPermission
    }

    if ($TAMLine -ilike "AssignRolePermission-*"){
        $TAMLine=$TAMLine -replace "AssignRolePermission-",'' # trim header
        $currentOU=new-OUIfNotExist -OUName $ouName -OUPath $OUpath
        #New-ADGroup -Name $TAMLine -Path $currentOU -GroupScope Global -GroupCategory Security -ErrorAction SilentlyContinue
        #Write-Warning "New group $TAMLine at $currentOU"
        if ($TAMLine -like '*,*'){
            $roleGroup=$TAMLine.Split(',')[0]
            $PermissionGroup=$TAMLine.Split(',')[1]
            Add-ADGroupMember -Members $RoleGroup -Identity $PermissionGroup -ErrorAction Continue -Verbose
        }
        else
        {
            write-warning $TAMLine
            write-error "AssignRolePermission-RoleGroupName,PermissionGroupName"
        }
    }
}

