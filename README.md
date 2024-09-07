    Active Directory
      _____ _                        __     _             
     |_   _(_) ___ _ __ ___    ___  / _|   (_) ___  _   _ 
       | | | |/ _ \ '__/ __|  / _ \| |_    | |/ _ \| | | |
       | | | |  __/ |  \__ \ | (_) |  _|   | | (_) | |_| |
       |_| |_|\___|_|  |___/  \___/|_|    _/ |\___/ \__, |
                                         |__/       |___/ 
                    Yet another Tiered Admin Model script...

# ADTiersOfJoy
A PowerShell script to harded Active Directory by deploying Active Directory Tiered Administration Model.

Background reading:
* [Microsoft describing Protecting Tier 0 the Modern Way](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/protecting-tier-0-the-modern-way/bc-p/4239218)
* [Microsoft describing how to protect domain admins](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-f--securing-domain-admins-groups-in-active-directory)
* [TrueSec describing their implementation to Tiered admin model](https://www.truesec.com/security/active-directory-tiering)
* [Quest descriving Tiered admin model](https://blog.quest.com/the-importance-of-tier-0-and-what-it-means-for-active-directory/)
* [Trimarc describing using restructed groups, via Group policy, to block higher tier accounts being used on lower tier machines](https://www.hub.trimarcsecurity.com/post/implementing-controls-in-active-directory-protecting-against-privileged-credential-sprawl)

The code:
* Creates OUs
* Creates security groups for roles and permissions
* Nests permissions groups into role groups
* Delegates permissions to OUs

You then: 
* link your existing GPOs to new OU structure
* Make GPOs to deny login to workstations and application servers with domain admin accounts (no cached domain admin creds on desktops)
* Update the domain join step of your desktop and server deployment automation. New service account for desktop deployment, not domain admin, with in role group to add desktops to T2 OU. New service account for server deployment, not domain admin, in role group to add servers to T1 OU
* Move over your users, groups, machines to the new OU structure following the Tiered Administration Model principles

(!) Test in a lab. Don't experiment in live envronment.  Replace group names with your own naming convention.  The structure is just an example. Remix to your own requirements.

To do: 
* Combine with [Pester](https://pester.io) tests to ensure Tiered Administration Model rules are followed (no lower tier accounts or groups in higher tier groups/roles). Maybe within [Maester framework](https://maester.dev)
* Set [authentication polices to shorten kerberos ticket lifecycle and force "Account is sensitive and cannot be delegated" on all T0 accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts#create-a-user-account-audit-for-authentication-policy-with-adac)

# Credits
Thanks to the following folks for sharing their code:
* Credit to joegasper @ https://gist.github.com/joegasper/3fafa5750261d96d5e6edf112414ae18
* Credit to przybylskirobert @ https://github.com/przybylskirobert/ADSecurity/blob/master/Tiering/Scripts/Set-OUUserPermissions.ps1
* Credit to SalutAToi @ https://github.com/SalutAToi/AD-Tier-Administration/blob/master/ACESkel.json  Je vous remercie
