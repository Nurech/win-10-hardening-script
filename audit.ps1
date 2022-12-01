$1_1 = "False"
$2 = "False"
$3 = "False"
$4 = "False"
$5 = "False"
$PUAProtection = "False"
$DeviceGuard = "False"

function initialize-audit {
    
    clear-host
    sleep 1 
    write-host "[+] ----->  PowerShell v$PSVersion`n" 
    checkAdministrativePrivilege
    testBlockRemoteCommands
    testFileAssociations
    testEnableNetworkprotection
    testEnableExploitProtection
    testWindowsDefender
}

function checkAdministrativePrivilege() {
    <#This function checks If the script can run with administrative privilege#>
    Write-Host "[?] Checking for administrative privileges ..`n"
    $isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)   
    If ($isAdmin) {	
        Write-Host "[+] ----->  Administrator`n"           
    } Else {
        Write-Host "[-] Some of the operations need administrative privileges.`n"            
        Write-Host "[*] Please run the script using an administrative account."
	    exit 
    }
}

function testBlockRemoteCommands() {
    $script:1_1 = Test-Path HKEY_LOCAL_MACHINE\Software\Microsoft\OLE
}

function testFileAssociations() {
    $res = cmd.exe /c "assoc .bat"
    $res1 = cmd.exe /c "assoc .chm"
    $res2 = cmd.exe /c "assoc .hta"
    Write-Host $res
    If ($res -like "*txtfile*" -And $res1 -like "*txtfile*" -And $res2 -like "*txtfile*") {
        Write-Host "All extensions good"
        $script:2 = "True"
    } Else {
        Write-Host "Some extensions bad"
        $script:2 = "False"
    }
}

function testEnableNetworkprotection() {
    $res = Get-MpPreference | Select-Object -Property EnableNetworkProtection
    If($res.EnableNetworkProtection -eq "0") {
        Write-Host "Enable Network Protection is 0"
        $script:3 = "False"
    }
    ElseIf($res.EnableNetworkProtection -eq "1") {
        Write-Host "Enable Network Protection is 1"
        $script:3 = "True"
    }

}

function testEnableExploitProtection() {
    $res = Get-ProcessMitigation | Select-Object PolicyFilePath
    If($res.PolicyFilePath -eq $null) {
        Write-Host "Enable Exploit Protection is null"
        $script:4 = "False"
    }
    ElseIf($res.PolicyFilePath -ne $null) {
        Write-Host "Enable Exploit Protection is not null"
        $script:4 = "True"
    }

}

function testWindowsDefender() {
    $res = Get-MpPreference | Select-Object PUAProtection
    $res1 = Get-MpPreference | Select-Object AttackSurfaceReductionRules_Actions


    If($res.PUAProtection -eq "0" -And $res1.AttackSurfaceReductionRules_Actions -eq $null) {
        Write-Host "Windows Defender is 0"
        $script:PUAProtection = "False"
    }
    ElseIf($res.PUAProtection -eq "1" -And $res1.AttackSurfaceReductionRules_Actions -ne $null) {
        Write-Host "Windows Defender is 1"
        $script:PUAProtection  = "True"
    }

    $res2 = Get-ItemPropertyValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\' -Name EnableVirtualizationBasedSecurity 

    If ($res2 -eq "1") {
        $script:DeviceGuard = "True"
    } Else {
        $script:DeviceGuard = "False"
    }

    If ($PUAProtection -eq "True" -And $DeviceGuard -eq "True") {
        $script:5 = "True"
    }

}

initialize-audit

echo ""
echo "###############################################################################################################"
echo ""
echo "Starting audit"
echo ""
echo "###############################################################################################################"
echo ""
echo "├─ 1 [no test] Create a restore point"
echo "│   └─ [$1_1] Block Remote Commands"
echo "├─ 2 [$2] File Associations"
echo "├─ 3 [$3] Enable Network Protection"
echo "├─ 4 [$4] Enable Exploit Protection"
echo "├─ 5 [$5] Windows Defender"
echo "│   └─ 5_1 [$PUAProtection] Potentially Unwanted Applications"
echo "│   └─ 5_2 [$DeviceGuard] Windows Defender Application Guard"
echo "├─ 6 [] Harden MS Office"
echo "│   └─ 6_1 [] Word, Excel, Powerpoint"
echo "├─ 7 [] General OS hardening"
echo "│   └─ 7_1 [] Enforce the Administrator role on common attack points"
echo "│   └─ 7_2 [] Prevent Kerberos from using DES or RC4"
echo "│   └─ 7_3 [] TCPIP parameters"
echo "│   └─ 7_4 [] Shared access (LSA)"
echo "│   └─ 7_5 [] Group Policy"
echo "│   └─ 7_6 [] Enable SMB/LDAP Signing"
echo "│   └─ 7_7 [] Enforce NTLMv2 and LM authentication"
echo "│   └─ 7_8 [] Disable script.exe, DLL Hijacking, IPv6, WinRM Service, NetBIOS, AutoRun"
echo "│   └─ 7_9 [] Windows Update Settings"
echo "│   └─ 7_10 [] Windows Remote Access Settings"
echo "├─ 8 [] Harden lsass to help protect against credential dumping"
echo "├─ 9 [] Disable the ClickOnce trust prompt"
echo "├─ 10 [] Enable Windows Firewall and configure some advanced options + logging"
echo "├─ 11 [] Biometrics"
echo "├─ 12 [] Disable weak TLS/SSL ciphers and protocols"
echo "├─ 13 [] Enable and Configure Internet Browser Settings"
echo "├─ 14 [] Windows 10 Privacy Settings"
echo "│   └─ 14_1 [] Disable location data, Windows GameDVR, consumer experience"
echo "├─ 15 [] Enlarge Windows Event Security Log Size"
echo "├─ 16 [] Enable Windows Event Detailed Logging"
echo "├─ 17 [] Uninstall unwanted programs"
echo "├─ 18 [] Edge hardening"
echo "├─ 19 [] Enable and Configure Google Chrome Internet Browser Settings"
echo "├─ 20 [] Enforce device driver signing"
echo ""
pause
