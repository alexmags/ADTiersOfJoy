    Active Directory
      _____ _                        __     _             
     |_   _(_) ___ _ __ ___    ___  / _|   (_) ___  _   _ 
       | | | |/ _ \ '__/ __|  / _ \| |_    | |/ _ \| | | |
       | | | |  __/ |  \__ \ | (_) |  _|   | | (_) | |_| |
       |_| |_|\___|_|  |___/  \___/|_|    _/ |\___/ \__, |
                                         |__/       |___/ 
                    Yet another Tiered Admin Model script...

# ADTiersOfJoy
A PowerShell script to deploy Active Directory Tiered Administration Model.

The code:
* Creates OUs
* Creates security groups
* Nests security groups into role groups
* Delegates permissions to OUs

(!) Test in a lab. Don't experiment in live envronment.  Replace group names with your own naming convention.  The structure is just an example. Remix to your own requirements.

To do: Combine with Pester tests to ensure Tiered Administration Model rules are followed (no lower tier accounts or groups in higher tier groups/roles) 

# Credits
Thanks to the following folks for sharing their code:
    * Credit to joegasper @ https://gist.github.com/joegasper/3fafa5750261d96d5e6edf112414ae18
    * Credit to przybylskirobert @ https://github.com/przybylskirobert/ADSecurity/blob/master/Tiering/Scripts/Set-OUUserPermissions.ps1
    * Credit to SalutAToi @ https://github.com/SalutAToi/AD-Tier-Administration/blob/master/ACESkel.json  Je vous remercie