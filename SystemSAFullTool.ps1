#Create all the functions to be used for information gathering
function Get-Startup {
   $a = Get-WmiObject -Class win32_startupcommand | select Location,Caption,Command
   $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.Startup.csv")) -NoTypeInformation 
}
function Get-Tasks {
    $a = Get-ScheduledTask | Select-Object TaskName,Description,State,Taskpath,URI,Triggers,Author
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.ScheduledTasks.csv")) -NoTypeInformation
}
function Get-ProcessHash {
    $processes = Get-Process | Select-Object -ExpandProperty Path 
    $a = foreach ($process in $processes){
        CertUtil -Hashfile $process MD5
    }
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.processhases.csv")) -NoTypeInformation
 }
function Get-ServiceHash { 
    $services = Get-WmiObject Win32_Service |  Select-Object -ExpandProperty Pathname
    $a = foreach ($service in $services){
        CertUtil -Hashfile $service MD5
    }
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.servicehashes.csv")) -NoTypeInformation
}
function Retrieve-Services {
    $a = Get-Service | Sort-Object Status -Descending
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.services.csv")) -NoTypeInformation
}
#process information combining wmi with PS to get usernames and commandline as well
function Retrieve-Processes {
  $ProcInfo1 = Get-WmiObject win32_process | select processname, ProcessId, CommandLine, ExecutablePath | Sort-Object processname
  foreach ($proc in $ProcInfo1){
   $ProcInfo2 = Get-Process -Id $proc.ProcessId -IncludeUserName | Select-Object UserName, Modules, Description
   $FullProcInfo = New-Object -TypeName psobject -Property @{
    PID = $proc.ProcessId
    User = $ProcInfo2.UserName
    ProcessName = $proc.processname
    CommandLine = $proc.CommandLine
    Path = $proc.ExecutablePath
    Modules = $ProcInfo2.Modules
    Description = $ProcInfo2.Description
    }
   $FullProcInfo | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.processes.csv")) -NoTypeInformation
 }
}
function Get-UserAccounts{
  $a = Get-WmiObject Win32_UserAccount | Select-Object Name,SID,Caption,Accounttype,LocalAccount,Description
  $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.user_accounts.csv")) -NoTypeInformation
}
function Get-OSInfo{
  $a = Get-WmiObject -Class win32_computersystem  | select PSComputername, Domain, Model, Manufacturer, EnableDaylightSavingsTime, PartOfDomain, Roles, SystemType, NumberOfProcessors, TotalPhysicalMemory, Username
  $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.operating_systems.csv")) -NoTypeInformation
}
#connection information and correlate it with the processID
function Get-Connections{
  $results = Invoke-Command { netstat -ano } | Select-String -Pattern '::','\]:','Active','Proto','\s+$' -NotMatch
  $a = $results | % {
     $socket = $_
     $pattern = '(^\s+(?<proto>[TCP]{3})\s+(?<LocalAddress>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):(?<LocalPort>[0-9]{1,5})\s+(?<RemoteAddress>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):(?<RemotePort>[0-9]{1,5})\s+(?<State>[\w]+)\s+(?<PID>[0-9]{1,5}))|(\s+(?<proto>[UDP]{3})\s+(?<LocalAddress>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):(?<LocalPort>[0-9]{1,5})\s+\*:\*\s+(?<PID>[0-9]{1,5}))'
       if ($socket -match $pattern)
       {
         New-Object psobject | Select @{N='Protocol';E={$Matches['proto']}},
                                      @{N='LocalAddress';E={$Matches['LocalAddress']}},
                                      @{N='LocalPort';E={$Matches['LocalPort']}},
                                      @{N='RemoteAddress';E={$Matches['RemoteAddress']}},
                                      @{N='RemotePort';E={$Matches['RemotePort']}},
                                      @{N='State';E={$Matches['State']}},
                                      @{N='PID';E={$Matches['PID']}},
                                      @{N='ProcessName';E={[System.Diagnostics.Process]::GetProcessById([int]$Matches['PID']).ProcessName};},
                                      @{N='ProcessStartTime';E={([System.Diagnostics.Process]::GetProcessById([int]$Matches['PID']).StartTime)};}
        }

    }
  $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.connections.csv")) -NoTypeInformation
}
function Get-MappedDrives{
  $a = Get-PSDrive | Select-Object Name, Provider, Root, CurrentLocation
  $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.mappeddrives.csv")) -NoTypeInformation
}
function Get-UserGroups{
    $a = Get-WmiObject -Class win32_group |select PSComputername, Caption, Domain, Name, Sid
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.UserGroups.csv")) -NoTypeInformation
}
function Get-Shares{
    $a = Get-WmiObject -Class win32_share  |select PSComputername, Name, Path, Description
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.shares.csv")) -NoTypeInformation
}

Function Find-SusFilterDrivers {
    $FilterEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName="Microsoft-Windows-FilterManager"} | ForEach-Object {
        [PSCustomObject] @{
            TimeCreated = $_.TimeCreated
            MachineName = $_.MachineName
            UserId = $_.UserId
            FilterDriver = $_.Properties[4].Value
            Message = $_.Message
        }
    }
    echo "Scanning for suspicious filter drivers. Any found will be compared against existing services:"
    $SuspectDrivers = $($FilterEvents | where-object {$_.FilterDriver -ine "FileInfo" -AND $_.FilterDriver -ine "WdFilter" -AND $_.FilterDriver -ine "storqosflt" -AND $_.FilterDriver -ine "wcifs" -AND $_.FilterDriver -ine "CldFlt" -AND $_.FilterDriver -ine "FileCrypt" -AND $_.FilterDriver -ine "luafv" -AND $_.FilterDriver -ine "npsvctrig" -AND $_.FilterDriver -ine "Wof" -AND $_.FilterDriver -ine "FileInfo" -AND $_.FilterDriver -ine "bindflt" -AND $_.FilterDriver -ine "PROCMON24" -AND $_.FilterDriver -ine "FsDepends"} | select -exp FilterDriver)
    $FilteredDrivers = @{}
    foreach ($driver in $SuspectDrivers){
        echo "Checking services for relevant drivers. Any which aren't present may indicate a filter driver which has since been removed, or an active rootkit filtering service registry keys."
        $a = gci REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\$driver
        if ($a -eq $null) {
            $FilteredDrivers += $driver
            }
    $FilteredDrivers | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.suspiciousfilterdrivers.csv")) -NoTypeInformation
    }
}

Function Get-UserPSHistory {
    $users = Get-ChildItem C:\Users
    $total = @{}
    foreach($user in $users.Name){
        if(Test-Path -Path  C:\Users\$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt){
            $psHistory = Get-Content C:\Users\$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
            $line = 0
            foreach($cmd in $psHistory){
                $result = @{}
                $result.add("CommandLine", $cmd)

                $prefix = $cmd.split()[0]
                $result.add("Prefix", $prefix)
                
                $result.add("User", $user.Name.toString()) 
                $result.add("Line", $line++)
                
                Add-Result -hashtbl $result
                $total += $result
        }
    }
    $total | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.userpshistory.csv")) -NoTypeInformation
}
}

Function Get-ActiveUnsignedDLLs {
    $a = (gps).Modules.FileName | get-authenticodesignature | ? Status -NE "Valid" | Format-List *
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.activeunsigneddlls.csv")) -NoTypeInformation
}

Function Get-LocalMemDump {
    $ss = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace Root\Microsoft\Windows\Storage
    Invoke-CimMethod -InputObject $ss -MethodName "GetDiagnosticInfo" -Arguments @{DestinationPath=([System.IO.Path]::Combine($SaveFolder,"localmemdump.dmp")); IncludeLiveDump=$true}
}

Function Get-ParentChildProcess {

    $runningprocesses = Get-CimInstance -ClassName Win32_Process | 
    Select-Object CreationDate, ProcessName, ProcessId,CommandLine, ParentProcessId

     $a = for($i=0;$i -le $runningprocesses.count; $i++)
    {
        $runningprocesses[$i]
    
        Write-Host("Process:")
        (Get-CimInstance -ClassName Win32_Process | Where-Object ProcessId -EQ $runningprocesses[$i].OwningProcess).ProcessName
        Write-Host("CMDLine:")
        (Get-CimInstance -ClassName Win32_Process | Where-Object ProcessId -EQ $runningprocesses[$i].OwningProcess).CommandLine
        Write-Host ("Parent:")
        (Get-CimInstance -ClassName Win32_Process | Where-Object ProcessId -EQ $runningprocesses[$i].ParentProcessId).ProcessName
        Write-Host("Parent CMDLine:")
        (Get-CimInstance -ClassName Win32_Process | Where-Object ProcessId -EQ $runningprocesses[$i].ParentProcessId).CommandLine
        }
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.parentchildpairs.csv")) -NoTypeInformation
}

Function Get-SuspiciousTasks {
    #Enumerate Tasks
    $tasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, Date, Author, Actions, Triggers, Description, State |
    Where-Object Author -NotLike 'Microsoft*' | Where-Object Author -NE $null | Where-Object Author -NotLike '*@%SystemRoot%\*'

    #for each task found, export in XML which will show any commands run
    $a = foreach ($task in $tasks)
    {
        Export-ScheduledTask -TaskName $task.TaskName
    }
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.suspicioustasks.csv")) -NoTypeInformation
}

Function Get-ActiveServiceDLLHashes {
    $a = Get-ItemProperty REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\*\* -ea 0 | where {($_.ServiceDll -ne $null)} | foreach {Get-FileHash -Algorithm MD5 $_.ServiceDll}
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.servicedllhashes.csv")) -NoTypeInformation
}

Function Find-SDDLHiddenServices {
    
    #find services hidden using SDDL for possible persistence(some common legitimate hidden services are WUDFRd,WUDFWpdFs,WUDFWpdMtp)
    $SDDLServices = Compare-Object -ReferenceObject (Get-Service | Select-Object -ExpandProperty Name | % { $_ -replace "_[0-9a-f]{2,8}$" } ) -DifferenceObject (gci -path hklm:\system\currentcontrolset\services |
    % { $_.Name -Replace "HKEY_LOCAL_MACHINE\\","HKLM:\" } | ? { Get-ItemProperty -Path "$_" -name objectname -erroraction 'ignore' } | 
    % { $_.substring(40) }) -PassThru | ?{$_.sideIndicator -eq "=>"}

    $a = foreach ($SDDLService in $SDDLServices)
    {
        Get-CimInstance -ClassName CIM_Service | Where-Object Name -EQ $SDDLService | fl *
    }
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.sddlservices.csv")) -NoTypeInformation
}

function Get-UserStartedServices {
    $a = Get-WmiObject -Class Win32_service | where {$_.StartMode -ne 'Auto' -and $_.State -eq 'Running'} 
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.userstartedservices.csv")) -NoTypeInformation
}

function Get-UserStoppedServices {
    $a = Get-WmiObject -Class Win32_service | where {$_.StartMode -eq 'Auto' -and $_.State -ne 'Running'}
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.userstoppedservices.csv")) -NoTypeInformation
}

function Get-DefenderExclusions {
    $a = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclustions'
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.defenderexclusions.csv")) -NoTypeInformation
}

function Get-NamedPipes {
    $a = Get-ChildItem -Path '*\\.pipe\*' | sort Fullname | Format-Table Fullname,Length,IsreadOnly,Exists,Extension,CreationTime,LastAccessTime
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.namedpipes.csv")) -NoTypeInformation
}

function Get-WMIEventConsumers {
    $a = Get-WmiObject -Class __EventConsumer | Format-Table
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.wmiconsumers.csv")) -NoTypeInformation
}

function Get-WMIEventFilters {
    $a = Get-WmiObject -Class __EventFilter -Namespace root\subscription | Format-Table Name,Query,PSComputername -Wrap
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.wmifilters.csv")) -NoTypeInformation
}

function Get-WMIFilterConsumerBindings {
    $a = Get-WmiObject -Class __Filtertoconsumerbinding -Namespace root\subscription | Format-Table Consumer,Filter,_SERVER -Wrap
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.wmibindings.csv")) -NoTypeInformation
}

function Get-UsedDLLs {
    $a = Get-Process | Format-List ProcessName, @{I="Modules";e={_.Modules | Out-String}} 
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.usedDLLs.csv")) -NoTypeInformation
}

function Get-UnsignedDrivers {
    $a = gci -path C:\Windows\System32\drivers -include *.sys -recurse -ea SilentlyContinue | Get-AuthenticodeSignature | where {$_.status -ne 'Valid'}
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.unsigneddrivers.csv")) -NoTypeInformation
}

function Get-UserFileTree {
    tree C:\Users | Out-File -FilePath ([System.IO.Path]::Combine($SaveFolder,"$pc.userfiletree.txt"))
}

function Get-UserInitLogonScripts {
    $logonScriptsArrayList = [System.Collections.ArrayList]@();
                 
    New-PSDrive HKU Registry HKEY_USERS -ErrorAction SilentlyContinue | Out-Null;
    Set-Location HKU: | Out-Null;

    $SIDS  += Get-ChildItem -Path HKU: | where {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | foreach {$_.PSChildName };

    foreach($SID in $SIDS){
       $logonscriptObject = [PSCustomObject]@{
           SID =""
           HasLogonScripts = ""
    
       };
       $logonscriptObject.sid = $SID; 
       $logonscriptObject.haslogonscripts = !((Get-ItemProperty HKU:\$SID\Environment\).userinitmprlogonscript -eq $null); 
       $logonScriptsArrayList.add($logonscriptObject) | out-null
       }
    $logonScriptsArrayList | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.initlogonscripts.csv")) -NoTypeInformation
}

function Get-NetworkShares {
    $userSIDs = Get-LocalUser | select SID
    $a = foreach ($userSID in $userSIDs){
        if($userSID) {
		        Get-ItemProperty -Path "registry::HKEY_USERS\$userSID\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\" -ErrorAction SilentlyContinue
            }
            else {
		        Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\ -ErrorAction SilentlyContinue
            }
        }
    $a | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.networkshares.csv")) -NoTypeInformation
}

function Get-RDPSessions {
    qwinsta | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.rdpsessions.csv")) -NoTypeInformation
}

function Get-RemotelyOpenedFiles {
    openfiles | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.remotelyopenedfiles.csv")) -NoTypeInformation
}

function Get-DNSCache {
    Get-DnsClientCache -Status Success | Select Entry,RecordName,RecordType,Status,Data| Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.dnscache.csv")) -NoTypeInformation
}

function Get-SMBSessionInfo {
    Get-SmbSession | Export-Csv -Path ([System.IO.Path]::Combine($SaveFolder,"$pc.smbsessions.csv")) -NoTypeInformation
}

# Make a GUI

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#create the form
$form = New-Object System.Windows.Forms.Form
$form.Width = 600
$form.Height = 600
$form.Text = "System Sitautional Awareness Tool"
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$form.MaximizeBox = $false

# Define text label 1
$textLabel1 = New-Object System.Windows.Forms.Label
$textLabel1.Left = 25
$textLabel1.Top = 15
$textLabel1.Text = 'Select a Function: '

# define text label 2
$textLabel2 = New-Object System.Windows.Forms.Label
$textLabel2.Left = 25
$textLabel2.Top = 300
$textLabel2.Text = 'Output Directory: '

# create text box for output directory
$textBox = New-Object System.Windows.Forms.TextBox
$textBox.Location = New-Object System.Drawing.Point(125,300)
$textBox.Size = New-Object System.Drawing.Size(325,20)
$form.Controls.Add($textBox)

# Create a button to open the folder browser dialog
$outputbutton = New-Object System.Windows.Forms.Button
$outputbutton.Text = "Browse"
$outputbutton.Location = New-Object System.Drawing.Point(450,300)
$outputbutton.Add_Click({
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select a folder to save the output"
    $folderBrowser.ShowNewFolderButton = $true
    if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $textBox.Text = $folderBrowser.SelectedPath
    }
})
$form.Controls.Add($outputbutton)

$Global:SaveFolder = ""

# Create a button to save the output
$saveButton = New-Object System.Windows.Forms.Button
$saveButton.Text = "Confirm"
$saveButton.Location = New-Object System.Drawing.Point(450,325)
$saveButton.Add_Click({
    $Global:SaveFolder = $textBox.Text
    if (-not [string]::IsNullOrEmpty($Global:SaveFolder)) {
        # Replace this with your actual output saving logic
        [System.Windows.Forms.MessageBox]::Show("Output will be saved to: " + $Global:SaveFolder)
    } else {
        [System.Windows.Forms.MessageBox]::Show("Please select a folder first.")
    }
})
$form.Controls.Add($saveButton)

# set cancel button
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Location = New-Object System.Drawing.Point(425,450)
#$cancelButton = [System.Windows.Forms.DialogResult]::Cancel
$cancelButton.Text = "Cancel"

# add button
$form.CancelButton = $cancelButton

$form.Controls.Add($cancelButton)

# add labels
$form.Controls.Add($textLabel1)
$form.Controls.Add($textLabel2)

$Global:checkedItems = @()

# create drop down to select funtcions
$listBox = New-Object System.Windows.Forms.CheckedListBox
$listBox.Location = New-Object System.Drawing.Point(150,15)
$listBox.Size = New-Object System.Drawing.Size(260,20)
$listBox.Height = 200
$listBox.CheckOnClick = $true

# add list box items
$listItems = 'Get-Startup','Get-Tasks','Get-ProcessHash','Get-ServiceHash','Retrieve-Services','Retrieve-Processes','Get-UserAccounts','Get-OSInfo','Get-Connections','Get-MappedDrives','Get-UserGroups','Get-Shares','Find-SusFilterDrivers','Get-UserPSHistory','Get-ActiveUnsignedDLLs','Get-LocalMemDump','Get-ParentChildProcess','Get-SuspiciousTasks','Get-ActiveServiceDLLHashes','Find-SDDLHiddenServices','Get-UserStartedServices','Get-UserStoppedServices','Get-DefenderExclusions','Get-NamedPipes','Get-WMIEventConsumers','Get-WMIEventFilters','Get-WMIFilterConsumerBindings','Get-UsedDLLs','Get-UnsignedDrivers','Get-UserFileTree','Get-UserInitLogonScripts','Find-SDDLHiddenServices','Get-NetworkShares','Get-RDPSessions','Get-RemotelyOpenedFiles','Get-DnsCache', 'Get-SMBSessionInfo'
$listItems | ForEach-Object { $listBox.Items.Add($_) }

$form.Controls.Add($listBox)

# Create a "Select All" checkbox
$selectAllCheckbox = New-Object System.Windows.Forms.CheckBox
$selectAllCheckbox.Text = "Select All"
$selectAllCheckbox.Location = New-Object System.Drawing.Point(250,220)
$selectAllCheckbox.Add_CheckedChanged({
    if ($selectAllCheckbox.Checked) {
        for ($i = 0; $i -lt $listBox.Items.Count; $i++) {
            $listBox.SetItemChecked($i, $true)
        }
    } else {
        for ($i = 0; $i -lt $listBox.Items.Count; $i++) {
            $listBox.SetItemChecked($i, $false)
        }
    }
})

$form.Controls.Add($selectAllCheckbox)

$button = New-Object System.Windows.Forms.Button
$button.Text = "Run"
$button.Location = New-Object System.Drawing.Point(75,450)
$button.Add_Click({
    $global:checkedItems = @()
    foreach ($item in $listBox.CheckedItems) {
        $global:checkedItems += $item
    }
    $button.DialogResult = [System.Windows.Forms.DialogResult]::OK
})

# Add the button to the form
$form.Controls.Add($button)

# Show the form
$result = $form.ShowDialog()


if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    #set variables and folders
    $pc = $env:COMPUTERNAME
    #directory must be created beforehand...make sure it is their, if not then create one
    if (!(Test-Path $Global:SaveFolder)) {
        Write-Host "Can't find $Global:SaveFolder...Creating it now." -ForegroundColor Red
        mkdir $Global:SaveFolder
    }
    #iterate through the functions checked
    foreach ($item in $global:checkedItems) {
        &$item
    }
}
