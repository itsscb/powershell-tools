# powershell-tools
A curated list of PowerShell-Scripts for the daily use

## Functions
### adm-AD-unlockUser()
Parameter: $username (string)
Unlocks a given Useraccount.

### adm-AD-PwdReset()
Parameter: $username (string), $pwd (string, optional), $changepwd (bool, optional)
Resets the password of a given Useraccount and sets the ChangePassword-Flag 

### adm-AD-UserData()
Parameter: $username (string)
Lists some useful information of the given Useraccount

### adm-DevicePing()
Parameter: $hostname (string)
Pings the given Host and prints the state on change until canceled with Ctrl + C

### adm-DeviceBitLockerKey()
Parameter: $hostname (string)
Reads the BitLocker-RecoveryKey from the Active Directory and prints it to the Console

### adm-AD-FixUser ()
Parameter: $hostname (string)
Checks AccountExpirationDate, PasswordExpired and LockedOut of a given Useraccount

### adm-FileExists()
Parameter: $filepath (string)
Checks if a file exists and prints the result until canceled with Ctrl + C

### adm-DHCPLookUp()
Parameter: $mac (string in format 00-00-00-00-00-00), $dhcpserver (string, optional)
Checks in which subnet a MAC-Address is located.

### adm-PrintersRemote()
Parameter: $hostname (string), $printserver (string, optional)
Adds printers to a given remote Host

### adm-PrintersRemoteRemove()
Parameter: $hostname (string), $printserver (string, optional)
Removes printers from a given remote Host

### adm-Troubleshoot()
Parameter: $hostname (string), $category (string, optional)
Runs the Windows-Troubleshooting of a given category on the given remote Host

### adm-GetSoftware()
Parameter: $hostname (string)
Gets the installed software of a given Host

### adm-CompareUsers()
Parameter: $user1 (string), $user2 (string)
Compares the AD-Groups of two given Useraccounts

### adm-ad-setPhoto()
Parameter: $username (string), $fotopath (string)
Sets the given Image as thumbnailPhoto in the given Useraccount 

### adm-ad-permissions()
Parameter: $username (string)
Lists the AD-Groups in which the given Useraccount is a member

### adm-ad-checkpermission()
Parameter: $username (string), $group (string)
Checks if the given Useraccount is member of a AD-Group with the given partial Name

### adm-ad-user()
Paramter: $surname (string)
Lists all Useraccounts with the given Surname

### adm-lastboot()
Parameter: $hostname (string)
Reads the last boot time of a given remote Host

### adm-moveUserFiles() 
Parameter: $source_host (string), $destination_host (string), $user (string)
Moves the Userfiles from one remote Host to another.
IMPORTANT: User must have been logged into both machines at least once && both Hosts have to be online.

### Copy-WithProgress()
Parameter: $Source (string), $Destination (string)
Copies Files and shows the progress

### adm-deviceInfo()
Parameter: $hostname (string)
Shows useful information of a given remote Host

### adm-printer-GetQueue()
Parameter: $printer (string), $printserver (string, optional)
Gets the Queue of PrintJobs of a given printer

### adm-RemoveStartupProgram()
Parameter: $hostname (string), $programname (string)
Removes Programs from the StartUp in the Registry of a given remote Host

### adm-GetStartupPrograms ()
Parameter: $hostname (string), $programname (string)
Lists Programs from the StartUp in the Registry of a given remote Host

### adm-GetMissingUpdates()
Parameter: $hostname (string)
Lists pending Windows Updates of a given remote Host

function adm-deviceDrivers()
Parameter: $hostname (string)
Lists all drivers of a given remote Host

function adm-driverInstallCab()
Parameter: $cabpath (string)
Installs all .cab-Files located in C:\temp\drivers on the local Host via pnputil
