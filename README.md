# powershell-tools
A curated list of PowerShell-Scripts for the daily use

## Functions
### adm-AD-unlockUser()
#### Parameter: $username (string)<br>
Unlocks a given Useraccount.

### adm-AD-PwdReset()
#### Parameter: $username (string), $pwd (string, optional), $changepwd (bool, optional)<br>
Resets the password of a given Useraccount and sets the ChangePassword-Flag 

### adm-AD-UserData()
#### Parameter: $username (string)<br>
Lists some useful information of the given Useraccount

### adm-DevicePing()
#### Parameter: $hostname (string)<br>
Pings the given Host and prints the state on change until canceled with Ctrl + C

### adm-DeviceBitLockerKey()
#### Parameter: $hostname (string)<br>
Reads the BitLocker-RecoveryKey from the Active Directory and prints it to the Console

### adm-AD-FixUser ()
#### Parameter: $hostname (string)<br>
Checks AccountExpirationDate, PasswordExpired and LockedOut of a given Useraccount

### adm-FileExists()
#### Parameter: $filepath (string)<br>
Checks if a file exists and prints the result until canceled with Ctrl + C

### adm-DHCPLookUp()
#### Parameter: $mac (string in format 00-00-00-00-00-00), $dhcpserver (string, optional)<br>
Checks in which subnet a MAC-Address is located.

### adm-PrintersRemote()
#### Parameter: $hostname (string), $printserver (string, optional)<br>
Adds printers to a given remote Host

### adm-PrintersRemoteRemove()
#### Parameter: $hostname (string), $printserver (string, optional)<br>
Removes printers from a given remote Host

### adm-Troubleshoot()
#### Parameter: $hostname (string), $category (string, optional)<br>
Runs the Windows-Troubleshooting of a given category on the given remote Host

### adm-GetSoftware()
#### Parameter: $hostname (string)<br>
Gets the installed software of a given Host

### adm-CompareUsers()
#### Parameter: $user1 (string), $user2 (string)<br>
Compares the AD-Groups of two given Useraccounts

### adm-ad-setPhoto()
#### Parameter: $username (string), $fotopath (string)<br>
Sets the given Image as thumbnailPhoto in the given Useraccount 

### adm-ad-permissions()
#### Parameter: $username (string)<br>
Lists the AD-Groups in which the given Useraccount is a member

### adm-ad-checkpermission()
#### Parameter: $username (string), $group (string)<br>
Checks if the given Useraccount is member of a AD-Group with the given partial Name

### adm-ad-user()
#### Paramter: $surname (string)<br>
Lists all Useraccounts with the given Surname

### adm-lastboot()
#### Parameter: $hostname (string)<br>
Reads the last boot time of a given remote Host

### adm-moveUserFiles() 
#### Parameter: $source_host (string), $destination_host (string), $user (string)<br>
Moves the Userfiles from one remote Host to another.<br>
IMPORTANT: User must have been logged into both machines at least once && both Hosts have to be online.

### Copy-WithProgress()
#### Parameter: $Source (string), $Destination (string)<br>
Copies Files and shows the progress

### adm-deviceInfo()
#### Parameter: $hostname (string)<br>
Shows useful information of a given remote Host

### adm-printer-GetQueue()
#### Parameter: $printer (string), $printserver (string, optional)<br>
Gets the Queue of PrintJobs of a given printer

### adm-RemoveStartupProgram()
#### Parameter: $hostname (string), $programname (string)<br>
Removes Programs from the StartUp in the Registry of a given remote Host

### adm-GetStartupPrograms ()
#### Parameter: $hostname (string), $programname (string)<br>
Lists Programs from the StartUp in the Registry of a given remote Host

### adm-GetMissingUpdates()
#### Parameter: $hostname (string)<br>
Lists pending Windows Updates of a given remote Host

### adm-deviceDrivers()
#### Parameter: $hostname (string)<br>
Lists all drivers of a given remote Host

### adm-driverInstallCab()
#### Parameter: $cabpath (string)<br>
Installs all .cab-Files located in C:\temp\drivers on the local Host via pnputil
