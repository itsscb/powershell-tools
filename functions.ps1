function adm-AD-unlockUser(){
    Param(
        [parameter(Mandatory=$true)][string]$username
        )

    $value = Get-ADUser -Filter { SamAccountName -eq $username} -Property LockedOut | Select-Object -Property SamAccountName, LockedOut

    if ($value.LockedOut -eq $true) {
        Unlock-ADAccount -Identity $username
        Write-Host -ForegroundColor Green 'The account of' $username 'was locked. Has been unlocked.'
    }
    else {
        Write-Host -ForegroundColor Red 'The account of' $username "wasn't locked. No action taken."
    }

}



function adm-AD-PwdReset(){
    Param(
        [parameter(Mandatory=$true)][string]$username,
        [parameter(Mandatory=$false)][string]$pwd,
        [parameter(Mandatory=$false)][string]$changepwd=$true
        )
    if ($pwd -eq $null) {
        $length = 12
        $nonAlphaChars = 3
        Add-Type -AssemblyName System.Web
        $pwd = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
        $value = ConvertTo-SecureString -String $pwd -AsPlainText -Force
    }
    else {
        $value = ConvertTo-SecureString -String $pwd -AsPlainText -Force
    }

    if ($changepwd -eq $null) {
        $changepwd = $true
    }
    else {
        $changepwd = $false
    }  
    Unlock-ADAccount -Identity $username
    Set-ADAccountPassword -Reset -NewPassword $value -Identity $username
    Set-ADUser -Identity $username -ChangePasswordAtLogon $changepwd
    Write-Host -ForegroundColor Green 'Set password of ' $username ' to ' $pwd   
}


function adm-AD-UserData() {
    Param(
    [parameter(Mandatory=$true)][string]$username
    )
    
    Get-ADUser -Identity $username -Properties * | Select DisplayName, Department, SamAccountName, Enabled, LockedOut,`
    PasswordExpired, PasswordNeverExpires, PasswordNotRequired, CannotChangePassword, PasswordLastSet, LastBadPasswordAttempt, `
    LastLogonDate, AccountExpirationDate, extensionAttribute13, EmailAddress, Homedirectory

}

function adm-DevicePing() {
    Param(
    [parameter(Mandatory=$true)][string]$hostname
    )
    $status = $none
    while ($true) {
        $date = Get-Date
        $ping = Test-Connection $hostname -Count 2 -Quiet
        if ( $ping -eq $true ) {
            if ($status -eq 'connected') {continue}
            elseif ($status -ne 'connected') {
                $status = 'connected'
                Write-Host -ForegroundColor Green $date.Year'-'$date.Month'-'$date.Day '/' $date.Hour':'$date.Minute':'$date.Second '|' $hostname '|' $status
            }
        }
        elseif ($ping -eq $false) {
            if ($status -eq 'not connected') {continue}
            elseif ($status -ne 'not connected') {
                $status = 'not connected'
                Write-Host -ForegroundColor Red $date.Year'-'$date.Month'-'$date.Day '/' $date.Hour':'$date.Minute':'$date.Second '|' $hostname '|' $status
            }
        }
        
    }    
}


function adm-DeviceBitLockerKey() {
    Param(
        [parameter(Mandatory=$true)][string]$hostname
        )

    $objComputer = Get-ADComputer $hostname
    $Bitlocker_Object = Get-ADObject -Filter { objectclass -eq 'msFVE-RecoveryInformation' } -SearchBase $objComputer.DistinguishedName -Properties 'msFVE-RecoveryPassword'
    if ($Bitlocker_Object -eq $null) {
        Write-Host -ForegroundColor Red 'No recoverykey found for '$hostname
    }

    elseif ($Bitlocker_Object -ne $null) {
        Write-Host -ForegroundColor Green 'BitLocker-RecoveryKey of '$hostname ': ' $Bitlocker_Object.'msFVE-RecoveryPassword'
    }
}


function adm-AD-FixUser () {
    Param(
    [parameter(Mandatory=$true)][string]$username
    )

    $date = Get-Date

    $user = adm-AD-UserData $username

    if ($user.Enabled -eq $false) {

        $user | Select DisplayName,Department,SamAccountName,Enabled
        Write-Host -ForegroundColor Red 'The account '$username ' is disabled'
        
    }
    elseif ($user.LockedOut -eq $true) {
        $user | Select DisplayName,Department,SamAccountName,LastBadPasswordAttempt,LockedOut
        adm-AD-unlockUser $username
    }
    elseif ($user.PasswordExpired -eq $true) {
        $user | Select DisplayName,Department,SamAccountName,PasswordLastSet,PasswordExpired
        Write-Host -ForegroundColor Red 'The password of '$username ' is expired'
        
    }
    elseif ($user.AccountExpirationDate -eq $null) {
        $user
        Write-Host -ForegroundColor Green 'No problems found with '$username
    }
    elseif ($user.AccountExpirationDate -le $date) {
        $user | Select DisplayName,Department,SamAccountName,AccountExpirationDate
        Write-Host -ForegroundColor Red 'The account of '$username ' is expired'
    }
   

    else {
        Write-Host -ForegroundColor Green 'No problems found with '$username
        $user
    }
}


function adm-FileExists() {
    Param(
    [parameter(Mandatory=$true)][string]$filepath
    )
    While ($true) {
        $now = [datetime]::Now
        if (Test-Path $filepath) {
            $temp = $filepath + ' exists - ' + $now
            Write-Host -ForegroundColor Green $temp
        }
        else {
            $temp = $filepath + " doesn't exist - " + $now
            Write-Host -ForegroundColor Red $temp
        }
        Start-Sleep -Seconds 60
    }
}


function adm-DHCPLookUp() {
    Param(
    [parameter(Mandatory=$true)][string]$mac,
    [parameter(Mandatory=$false)][string]$dhcpserver='DHCPSERVER' # Name of your DHCP-Server 
    )
    foreach ($scope in Get-DhcpServerv4Scope -ComputerName $dhcpserver){Get-DhcpServerv4Lease -ComputerName $dhcpserver `
    -AllLeases -ScopeId $scope.ScopeId | Where-Object {$_.clientid -match $mac} | fl}
}



function adm-PrintersRemote() {
    Param(
    [parameter(Mandatory=$true)][string]$hostname,
    [parameter(Mandatory=$false)][string]$printserver='PRINTSERVER' # Name of your Print-Server
    )
    
    $printers = [System.Collections.ArrayList]@()
    $printerList = Get-Printer -ComputerName lwesv0125 | Where Shared -eq $true

    Write-Host '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'
    Write-Host '@@@                                                                                        @@@'
    Write-Host '@@@                                   For every printer:                                   @@@'
    Write-Host '@@@                         Enter name of the printer and press "Return"                   @@@'
    Write-Host '@@@                                                                                        @@@'
    Write-Host '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'

    While ($uInput -ne '') {

        $uInput = Read-Host 'Please enter the name of the printer'
        $printers.Add($uInput)
    }

    foreach ($printer in $printers) {
        Write-Host ''
        Write-Host ''
        if ($printer -ne '') {
            $tmppr = $printerList | Where-Object -Property ShareName -eq $printer
            try {
                $prStr = $tmppr.ShareName.ToString()
            }
            catch {
                
                Write-Host $printer "can't be added - not found."
                Write-Host 'Please check the name of the printer.'
                Write-Host ''
                Write-Host ''
                Write-Host ''
                $errLvl = $true
            }
            if ($errLvl -ne $true) {
                $prStr = '\\'+$printserver+'\'+$prStr
                
                Invoke-Command -ComputerName $hostname -ScriptBlock { RUNDLL32 PRINTUI.DLL,PrintUIEntry /ga /n$Using:prStr }
                Write-Host $printer 'has been added.'
            }
            $errLvl = $false
        }
    }
    Invoke-Command -ComputerName $hostname -ScriptBlock { Restart-Service -Name Spooler }
}

function adm-PrintersRemoteRemove() {
    Param(
    [parameter(Mandatory=$true)][string]$hostname,
    [parameter(Mandatory=$false)][string]$printserver='PRINTSERVER' # Name of your Print-Server
    )
    if ($hostname -eq $none) {
        $hostname = Read-Host 'Please enter the hostname of the remote computer'
    }
    
    $printers = [System.Collections.ArrayList]@()
    $printerList = Get-Printer -ComputerName $printserver | Where Shared -eq $true

    Write-Host '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'
    Write-Host '@@@                                                                                        @@@'
    Write-Host '@@@                                   For every printer:                                   @@@'
    Write-Host '@@@                         Enter name of the Printer and press "Return"                   @@@'
    Write-Host '@@@                                                                                        @@@'
    Write-Host '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'

    While ($uInput -ne '') {

        $uInput = Read-Host 'Please enter the name of the printer that should be removed'
        $printers.Add($uInput)
    }

    foreach ($printer in $printers) {
        Write-Host ''
        Write-Host ''
        if ($printer -ne '') {
            $tmppr = $printerList | Where-Object -Property ShareName -eq $printer
            try {
                $prStr = $tmppr.ShareName.ToString()
            }
            catch {
                
                Write-Host $printer "can't be removed - not found."
                Write-Host 'Please check the name of the printer.'
                Write-Host ''
                Write-Host ''
                Write-Host ''
                $errLvl = $true
            }
            if ($errLvl -ne $true) {
                $prStr = '\\'+$printserver+'\'+$prStr
                
                Invoke-Command -ComputerName $hostname -ScriptBlock { RUNDLL32 PRINTUI.DLL,PrintUIEntry /gd /n$Using:prStr }
                Write-Host $printer 'has been removed.'
            }
            $errLvl = $false
        }
    }
    Invoke-Command -ComputerName $hostname -ScriptBlock { Restart-Service -Name Spooler }
}

function adm-Troubleshoot() {
    Param(
    [parameter(Mandatory=$true)][string]$hostname,
    [parameter(Mandatory=$false)][string]$category
    )
    if ($category -eq $none) { 
        Write-Host ''
        Write-Host 'Please select a category of the troubleshoot:'
        Write-Host ''
        Write-Host 'Apps'
        Write-Host 'Audio'
        Write-Host 'BITS'
        Write-Host 'Bluetooth'
        Write-Host 'Device'
        Write-Host 'DeviceCenter'
        Write-Host 'IEBrowseWeb'
        Write-Host 'IESecurity'
        Write-Host 'Keyboard'
        Write-Host 'Networking'
        Write-Host 'PCW'
        Write-Host 'Power'
        Write-Host 'Printer'
        Write-Host 'Search'
        Write-Host 'Speech'
        Write-Host 'Video'
        Write-Host 'WindowsMediaPlayerConfiguration'
        Write-Host 'WindowsMediaPlayerMediaLibrary'
        Write-Host 'WindowsMediaPlayerPlayDVD'
        Write-Host 'WindowsUpdate'
        
        Write-Host ''
        Write-Host ''
        Write-Host 'Within a PSSession:' -ForegroundColor DarkRed
        Write-Host 'Command 1: $variable = Get-TroubleshootingPack -Path "C:\Windows\Diagnostics\System\" + category' -ForegroundColor DarkYellow
        Write-Host 'Command 2: Invoke-TroubleshootingPack -Pack $variable' -ForegroundColor DarkYellow
        Write-Host ''
        Write-Host ''
        $category = Read-Host 'Category'
    }
    Enter-PSSession $hostname
    $trPath = 'C:\Windows\Diagnostics\System\'+$category
    $trouble = Get-TroubleshootingPack -Path $trPath
    Invoke-TroubleshootingPack -Pack $trouble
    Exit
}


function adm-GetSoftware() {
    Param(
    [parameter(Mandatory=$true)][string]$hostname
    )
    if (Test-Connection $hostname -Count 1 -Quiet) {
        $apps = Invoke-Command $hostname { Get-WmiObject -ComputerName $Using:hostname -Class Win32_Product}
        $apps | Select Name, Vendor, Version, Caption | Sort-Object -Property Name | FT
    }
    else {
        Write-Host $hostname 'is not online - cannot check installed software.'
    }
}

function adm-UninstallSoftware ($hostname, $name) {
    $name = $name.ToString()
    Invoke-Command $hostname { $app = Get-WmiObject -Class Win32_Product | Where-Object { 
    $_.Name -match $Using:name }
; $app.Uninstall()}

}


function adm-ReinstallSoftware ($hostname, $name) {
    $name = $name.ToString()
    Invoke-Command $hostname { $app = Get-WmiObject -Class Win32_Product | Where-Object { 
    $_.Name -match $Using:name }
; $app.Reinstall()}

}


function adm-CompareUsers() {
    Param(
    [parameter(Mandatory=$true)][string]$user1,
    [parameter(Mandatory=$true)][string]$user2
    )

    $groups1 = Get-ADPrincipalGroupMembership $user1 | Select -ExpandProperty name
    $groups2 = Get-ADPrincipalGroupMembership $user2 | Select -ExpandProperty name

    $dif1 = Compare-Object -ReferenceObject $groups1 -DifferenceObject $groups2 | Where-Object {
        $_.SideIndicator -eq '<=' } | Select -ExpandProperty InputObject


    $dif2 = Compare-Object -ReferenceObject $groups1 -DifferenceObject $groups2 | Where-Object {
        $_.SideIndicator -eq '=>' } | Select -ExpandProperty InputObject

    if ($groups1.Count -gt $groups2.Count) {
        $shared = $groups1 | %{ if ($groups2 -contains $_) { $_ } }
    }
    else {
        $shared = $groups2 | %{ if ($groups1 -contains $_) { $_ } }
    }
    $data = @{$user1=@{'Groups'=$groups1;'Exclusive Groups'=$dif1;'Excluded Groups'=$dif2};$user2=@{'Groups'=$groups2;`
    'Exclusive Groups'=$dif2;'Excluded Groups'=$dif1};'Shared Groups'=$shared}
    Write-Host ''
    Write-Host $user1 'Exclusive Groups:' -ForegroundColor Yellow
    $data.$user1.'Exclusive Groups' | Sort-Object
    Write-Host ''
    Write-Host ''
    Write-Host $user2 'Exclusive Groups:' -ForegroundColor Yellow
    $data.$user2.'Exclusive Groups' | Sort-Object
    Write-Host ''
    Write-Host ''
    Write-Host 'Shared Groups:' -ForegroundColor Yellow
    $data.'Shared Groups' | Sort-Object
}


function adm-ad-setPhoto() {
    Param(
    [parameter(Mandatory=$true)][string]$username,
    [parameter(Mandatory=$true)][string]$fotopath
    )
    Set-ADUser $username -Clear thumbnailPhoto
    Start-Sleep -Seconds 5
    $photo = [byte[]](Get-Content $fotopath -Encoding byte)
    Set-ADUser $username -Replace @{thumbnailPhoto=$photo}
}

function adm-ad-permissions() {
    Param(
    [parameter(Mandatory=$true)][string]$username
    )
    $user = $username.ToUpper().Trim() 
    $Res = (Get-ADPrincipalGroupMembership $user | Measure-Object).Count 
    If ($Res -GT 0) { 
        Write-Host "$user is member of the following Groups:" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Get-ADPrincipalGroupMembership $user | Select-Object -Property Name, GroupScope, GroupCategory | Sort-Object -Property Name | FT -A 
    } 
}

function adm-ad-checkpermission() {
    Param(
    [parameter(Mandatory=$true)][string]$username,
    [parameter(Mandatory=$true)][string]$group
    )
    $user = $username.ToUpper().Trim() 
    $Res = (Get-ADPrincipalGroupMembership $user | Measure-Object).Count 
    If ($Res -GT 0) { 
        $permissions = Get-ADPrincipalGroupMembership $user
    }
    $permissions = $permissions | Sort-Object -Property Name
    Write-Host $user 'is member of the following Groups:' -ForegroundColor Cyan
    Write-Host '========================================' -ForegroundColor Cyan
    $permissions.Name | %{ if( $_ -match $group) { Write-Host $_ }} 
}


function adm-ad-user() {
    Param(
    [parameter(Mandatory=$true)][string]$surname
    )
    Get-ADUser -Properties * -Filter {Surname -like $surname} | Select Name, SamAccountName, `
    Enabled, LockedOut,`
    PasswordExpired, LastBadPasswordAttempt, `
    AccountExpirationDate | Sort-Object Name | FT
}

function adm-lastboot() {
    Param(
    [parameter(Mandatory=$true)][string]$hostname
    )
    if ((Test-Connection -Count 1 -Quiet -ComputerName $hostname) -eq $true) {
        $return = Invoke-Command -ComputerName $hostname { Get-WinEvent -FilterHashtable @{Logname='System';ID=1074} -MaxEvents 5000 | `
        Select TimeCreated, Message }
        Write-Host 'Last Reboot Time: '$return[0].TimeCreated -ForegroundColor Yellow
    }
    else {
        Write-Host $hostname ' is offline or not available' -ForegroundColor Red
    }
}




function adm-moveUserFiles() {
    Param(
    [parameter(Mandatory=$true)][string]$source_host,
    [parameter(Mandatory=$true)][string]$destination_host,
    [parameter(Mandatory=$true)][string]$username
    )
    if ((Test-Connection $host_source -Count 1 -Quiet) -and (Test-Connection $destination_host -Count 1 -Quiet)) {
        $folders = 'Documents','Pictures','Favorites','Downloads','Videos', 'Music', 'Desktop','Links'
        $count = $folders.Count
        $ticker = 0
        $base_source = '\\'+$source_host+'\c$\Users\'+$username+'\'
        $base_destination = '\\'+$destination_host+'\c$\Users\'+$username+'\'
        if (Test-Path $base_destination) {
            $folders | %{ Copy-WithProgress -Source ($base_source+$_) -Destination ($base_destination+$_) }
        }
        else {
            Write-Host 'User must have been logged in on '$host_destination ' at least once!' -ForegroundColor Red
        }
    }
    else {
        Write-Host 'At least one host is not available/offline' -ForegroundColor Red
    }

}


Function Copy-WithProgress {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)] $Source,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)] $Destination
        )

    $Source=$Source.tolower()
    $Filelist=Get-Childitem $Source –Recurse
    $Total=$Filelist.count
    $Position=0
    foreach ($File in $Filelist) {

        $Filename=$File.Fullname.tolower().replace($Source,'')
        $DestinationFile=($Destination+$Filename)
        Write-Progress -Activity "Copying data from $source to $Destination" -Status "Copying File $Filename" -PercentComplete (($Position/$total)*100)
        Copy-Item $File.FullName -Destination $DestinationFile -Force
        $Position++
    }
 }

 Function adm-deviceInfo {
    [CmdletBinding()]
    Param (
        [string]$hostname = $env:ComputerName
    )

    try {
        $SystemEnclosure = Get-CimInstance win32_systemenclosure -computername $hostame -ErrorAction Stop
        $OS = Get-CimInstance Win32_OperatingSystem -Computername $hostname -ErrorAction Stop
    }
    catch {
        Write-Error "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
        break
    }

    #Creating Hash table from variables
    $PCInfo = @{
        Manufacturer   = $SystemEnclosure.Manufacturer
        PCName         = $OS.CSName
        OS             = $OS.Caption
        Architecture   = $OS.OSArchitecture
        AssetTag       = $systemenclosure.serialnumber;
        OSVersion      = $OS.Version
        InstallDate    = $OS.InstallDate
        LastBootUpTime = $OS.LastBootUpTime
        BIOSVersion    = (Get-WmiObject -Class Win32_BIOS -ComputerName $hostname | Select SMBIOSBIOSVersion).SMBIOSBIOSVersion
    }

    #Writing to Host
    Write-Host " "
    Write-Host "Computer Info" -Foregroundcolor Cyan
    Write-Host "If not run on a Dell machine AssetTag is the Serial Number" -Foregroundcolor Yellow

    #Display Hash Table
    $PCInfo.getenumerator() | Sort-Object -property name | Format-Table -autosize

    #Writing to Host
    Write-Host "Computer Disk Info" -Foregroundcolor Cyan

    #Display Drives
    Get-CimInstance win32_logicaldisk -filter "drivetype=3" -computer $hostname |
    Format-Table -Property DeviceID, Volumename, `
    @{Name = "SizeGB"; Expression = { [math]::Round($_.Size / 1GB) } }, `
    @{Name = "FreeGB"; Expression = { [math]::Round($_.Freespace / 1GB, 2) } }, `
    @{Name = "PercentFree"; Expression = { [math]::Round(($_.Freespace / $_.size) * 100, 2) } }

    #Writing to Host
    Write-Host "Network Information" -Foregroundcolor Cyan

    Get-CimInstance win32_networkadapterconfiguration -computer $hostname | Where-Object { $null -ne $_.IPAddress } |
    Select-Object IPAddress, DefaultIPGateway, DNSServerSearchOrder, IPSubnet, MACAddress, Caption, DHCPEnabled, DHCPServer, DNSDomainSuffixSearchOrder |
    Format-List
}


function adm-printer-GetQueue () {
    Param(
    [parameter(Mandatory=$true)][string]$printer,
    [parameter(Mandatory=$false)][string]$printserver='PRINTSERVER' # Name of your Print-Server
    )
    $printer = Get-Printer -ComputerName $printserver -Name $printer
    $jobs = Get-PrintJob -PrinterObject $printer
    if ($jobs -ne $null) {
        Write-Host ""'
            
Queued Print Jobs'"" -ForegroundColor Cyan
        $jobs | Format-Table
    }
    else {
        Write-Host 'No queued Print Jobs.' -ForegroundColor Green
    }

}


function adm-RemoveStartupProgram() {
    Param(
    [parameter(Mandatory=$true)][string]$hostname,
    [parameter(Mandatory=$true)][string]$programname
    )
    if (Test-Connection -Count 1 -Quiet $hostname) {
        Invoke-Command $hostname {
            New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS ; `
            Get-CimInstance Win32_StartupCommand |`
            Where-Object { $_.Name -match $programname } |`
            Select Name, Location | `
            %{ 
                $index = $_.Location.IndexOf('\') ; `
                if ($index -gt 0) {
                $path = $_.Location.insert($index,':') ; `
                }
                Remove-ItemProperty -path $path -Name $_.Name 
            } 
        }
    }
    
}


function adm-GetStartupPrograms () {
    Param(
    [parameter(Mandatory=$true)][string]$hostname
    )
    if (Test-Connection -Count 1 -Quiet $hostname) {
        Invoke-Command $hostname { 
        Get-CimInstance Win32_StartupCommand |`
        Where-Object { $_.Caption -match $programname } |`
        Select Name, Location | FT
        }
    }
    else {
        Write-Host $hostname 'cannot be reached or is offline' -ForegroundColor Red
    }
    
}

function adm-GetMissingUpdates() {
    Param(
    [parameter(Mandatory=$true)][string]$hostname
    )
    if (Test-Connection -Count 1 -Quiet $hostname) {
        Invoke-Command $hostname { 
            $UpdateSession = New-Object -ComObject Microsoft.Update.Session
            $UpdateSearcher = $UpdateSession.CreateupdateSearcher()
            $Updates = @($UpdateSearcher.Search("IsHidden=0 and IsInstalled=0").Updates)
            $Updates | Select-Object Title
        }
    }

    
}

function adm-deviceDrivers() {
    Param(
    [parameter(Mandatory=$true)][string]$hostname
    )
    if(-not (Test-Connection -Count 1 -Quiet $hostname)) { return }
    Write-Host 'List of drivers of'$hostname -ForegroundColor Cyan
    gwmi -Query "SELECT * FROM Win32_PnPSignedDriver" -ComputerName $hostname | Where-Object -Property DeviceName -ne $null |
    Sort DeviceName | 
    Select DeviceName, @{Name="DriverDate";Expression={[System.Management.ManagementDateTimeconverter]::ToDateTime($_.DriverDate).ToString("MM/dd/yyyy")}}, DriverVersion

}



function adm-driverInstallCab() {
    Param(
    [parameter(Mandatory=$true)][string]$cabpath
    )
    if (Test-Path $cabpath) {
        Write-Progress -Activity "Installing drivers" -Status "Creating directory C:\temp\drivers\" -PercentComplete 0
        if (Test-Path C:\temp\drivers) {
            Set-Location C:\temp
            Remove-Item -Path drivers -Force -Recurse
        }
        New-Item -ItemType Directory -Path C:\temp\drivers
        Write-Progress -Activity "Installing drivers" -Status "Exporting CAB-File to C:\temp\drivers\ | This may take a while!" -PercentComplete 2
        Expand $cabpath -F:* C:\temp\drivers\. | Out-Null
        $inffiles = Get-ChildItem -Path C:\temp\drivers -Filter *.inf -Recurse | Select FullName, PSChildName
        $infcount = $inffiles.count
        $pos = 0
        foreach ($inf in $inffiles) {
            $name = $inf.PSChildName
            Write-Progress -Activity "Installing drivers" -Status "Installing driver $name" -PercentComplete (($pos/$infcount)*100)
            pnputil /i /a $inf.FullName
            $pos++
        }
    }
    else {
        Write-Host $cabpath "not found!" -ForegroundColor Red
    }
}
