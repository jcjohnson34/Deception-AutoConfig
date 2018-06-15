<#
AutoConfig Logic:

Updated logic - don't install docker on every box, just a single server and then port forward from each system to the dockerized artillery/spidertrap/etc

Endpoint/Server capabilities
1. Check what services are running (port-based).  Based on services, set firewall and port forwarding rules to open ports and send them to Artillery IP

2. Create Honey Directory and set up object access auditing.  Make sure you're monitoring for event 4663 on this directory!

3. If Windows, inject scheduled task with honey creds

Server capabilities
4. If DNS server, inject a new zone (if it doesn't exist) and set zone transfers to allowed

#>


Param(
    [String]$honeyPortIP = "172.21.202.95",
    [String]$HoneyDirectory = "C:\Data",
    [String]$schTaskDomain = "jj",
    [String]$schTaskUsername = "admin",
    [String]$schTaskPassword = "P@ssw0rd",
    [String]$newDNSZone = "paymentsystems.jj.local",
    [switch]$Verbose
)
if($Verbose){  
    $oldverbose = $VerbosePreference  
    $VerbosePreference = "continue"  
}  
$HoneyPorts = New-Object System.Collections.ArrayList
$HoneyPorts.AddRange(("21","22","23","25","53","80","110","135","137","139","445","16993","5800","8080","10000","1337","1433","1521","1723","44443"))    

# 1. Determine which ports should be opened
#To Do - break this out so that users can send honeyports to different systems (e.g. 80 to system runnin SpiderTrap, 22 to system running Kippo, etc.)
function forwardHoneyPorts($honeyPortIP){
    $functionResult = "Fail"

    $resetPortFwd = "netsh interface portproxy reset"
    Invoke-Expression $resetPortFwd
    Write-Verbose "Reset existing port forwarding configuration. Setting up port forwarding to Artillery VM for all honeyports available on this host."

    $currentlyListeningPorts = Get-NetTCPConnection -State Listen | Where-Object {$_.RemoteAddress -eq "0.0.0.0"} |Select-Object -ExpandProperty LocalPort

    [System.Collections.ArrayList]$portsToNotExpose = @(Compare-Object -ExcludeDifferent -IncludeEqual $HoneyPorts $currentlyListeningPorts | Select-Object -ExpandProperty InputObject)

    #If honeyports are already being used, exclude them from Artillery ports
    foreach($duplicatePort in $portsToNotExpose){
        $HoneyPorts.Remove($duplicatePort)
        Write-Verbose "Removing port $duplicatePort since this host is already listening on it."
    }
    
    #Open Windows Firewall for Artillery Ports
    Write-Verbose "Opening Windows firewall for Artillery Ports. If you disable this, make sure you run 'Remove-NetFirewallRule -DisplayName `"HoneyPorts`"'!!"
    if(Get-NetFirewallRule -DisplayName 'HoneyPorts' -ErrorAction SilentlyContinue){
        #Remove rule and create new one just in case ports have changed
        Remove-NetFirewallRule -DisplayName 'HoneyPorts' | Out-Null
    }
    New-NetFirewallRule -DisplayName 'HoneyPorts' -Profile @('Domain', 'Private') -Direction Inbound -Action Allow -Protocol TCP -LocalPort $HoneyPorts -Enabled True | Out-Null
    $auditPolicyExpression = "Auditpol /set /category:`"System`" /SubCategory:`"Filtering Platform Connection`" /success:enable /failure:enable"
    Invoke-Expression $auditPolicyExpression | Out-Null
    foreach($port in $HoneyPorts){
        $portFwdCommand = "netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=$port connectaddress=$honeyPortIP connectport=$port"
        Invoke-Expression $portFwdCommand | Out-Null
    }
    
    #Check for success
    if(Get-NetFirewallRule -DisplayName 'HoneyPorts' -ErrorAction SilentlyContinue){
        $functionResult = "Success" 
    }
    $functionResult
}

function createHiddenFolders($TargetFolder) {
    $functionResult = "Fail"
    if(!(Test-Path $TargetFolder)){
         #Create Directory
        New-Item -ItemType Directory -Force -Path $TargetFolder | Out-Null
        attrib +h $TargetFolder
    }  

    #Update Object Access Auditing Policy (if not already enabled via GPO)
    $AuditExp = "auditpol /set /subcategory:`"File System`" /success:enable /failure:enable | Out-Null"
    Invoke-Expression $AuditExp |Out-Null
    #Set up Auditing on directory
    $AuditUser = "Everyone"
    $AuditRules = "Read,ListDirectory,ReadAndExecute,ReadAttributes,Traverse,Write"
    $InheritType = "ContainerInherit,ObjectInherit"
    $AuditType = "Success"
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule($AuditUser,$AuditRules,$InheritType,"None",$AuditType)
    $ACL = Get-Acl $TargetFolder
    $ACL.SetAuditRule($AccessRule)
    $ACL | Set-Acl $TargetFolder

    if(Test-Path $TargetFolder) {
        $functionResult = "Success"
    }
    $functionResult
}
function createHoneySchTask($domain, $username, $password){
    $functionResult = "Fail"
    $runAsUser = $domain + "\" + $username
    $schTasksExpression = "schtasks /create /tn `"Backup Data`" /tr cmd.exe /sc daily /ru $runAsUser /rp $password 2>&1"
    Invoke-Expression $schTasksExpression | Out-Null

    $checkSchTasksExpression = "schtasks /query /tn `"Backup Data`" 2>&1"
    $checkTask = Invoke-Expression $checkSchTasksExpression
    if($checkTask[0] -notlike "*ERROR*"){
        $functionResult = "Success"
    }
    $functionResult
}

function createDNSZone($newDNSZone) {
    #Create zone
    Add-DnsServerPrimaryZone -Name $newDNSZone -ReplicationScope Forest 
    #Enable zone transfers
    Set-DnsServerPrimaryZone -Name $newDNSZone -SecureSecondaries TransferAnyServer 
}

$server = 0
#Determine if we're running on Server or Workstation OS
$OSVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
if($OSVersion -like "*Server*" ){
    $server = 1
}

#1. Check what services are running (port-based).  Based on services, set firewall and port forwarding rules to open ports and send them to Artillery IP
Write-Host "STEP 1: Setting up Honey Ports"
$honeyPorts = forwardHoneyPorts $honeyPortIP
if($honeyPorts -eq "Success"){
    Write-Host -ForegroundColor Green "Successfully forwarded ports to $honeyPortIP.`n"
}
else{
    Write-Host -ForegroundColor Red "Something went wrong when configuring honey ports.  Re-run script with -Verbose switch for more details.`n"
}


#2. Create Honey Directory and set up object access auditing.  Make sure you're monitoring for event 4663 on this directory!
Write-Host "STEP 2: Creating hidden honey directory."

$hiddenDir = createHiddenFolders $HoneyDirectory
if($hiddenDir -eq "Success"){
    Write-Host -ForegroundColor Green "Successfully set up honeydirectory at $HoneyDirectory.  Make sure you watch for event ID 4663 on this directory.`n"
}
else{
    Write-Host -ForegroundColor Red "Could not create Honey Directory.`n"
}

#3. If Windows, inject scheduled task with honey creds
Write-Host "STEP 3: Creating scheduled task with fake credentials."
$task = createHoneySchTask $schTaskDomain $schTaskUsername $schTaskPassword
if($task -eq "Success"){
    Write-Host -ForegroundColor Green "Successfully set up scheduled task with honey credentials.  Watch for attempts to log in using $schTaskUsername"
    Write-Host -ForegroundColor Yellow "IMPORTANT: The user account set up in the scheduled task is still live.  Disable logon hours with: '`$logonHours = @{"logonHours" = [byte[]]`$hours=@(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)}; set-aduser `$username -replace `$logonHours' `n"
}
else{
    Write-Host -ForegroundColor Red "Failed to create scheduled task.  Make sure $schTaskUsername has temporary logon privileges for the duration of this script's execution.`n"
}

###Server capabilities
if($server -eq 1){
    $DNSRole = 0
    if($(Get-WindowsFeature DNS | Select-Object -ExpandProperty "InstallState") -notmatch "Available"){
        $DNSRole = 1
    }
    #4. If DNS server, inject a new zone (if it doesn't exist) and set zone transfers to allowed
    if($DNSRole -eq 1){
        createDNSZone $newDNSZone
        Write-Host -ForegroundColor Green "Set up new DNS Zone: $newDNSZone and enabled zone transfers. Make sure you watch for event ID 6001 to indicate zone transfers. `n"
    }
    else{
        Write-Host "DNS Server not running on this server. Skipping fake zone creation. `n"
    }
}

else{
    Write-Host "System is not running a server OS. Skipping server-side configs.`n"
}

if($Verbose){  
    $VerbosePreference = $oldverbose  
}  
