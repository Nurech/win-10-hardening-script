
$1_1 = Test-Path HKEY_LOCAL_MACHINE\Software\Microsoft\OLE


function initialize-audit {
    
    clear-host
    sleep 1 
    write-host "[+] ----->  PowerShell v$PSVersion`n" 
    checkAdministrativePrivilege
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

initialize-audit


echo "###############################################################################################################"
echo ""
echo "Starting audit"
echo ""
echo "###############################################################################################################"
echo ""
echo "├─ 1 [no test] Create a restore point"
echo "│   └─ [$1_1] Block remote commands"
echo "├─ 2 [] File associations"
echo "├─ 3 [] Enable Network protection"
echo "├─ 4 [] Enable exploit protection"
echo "├─ 5 [] Windows Defender"
echo "│   └─ 5_1 [] Updates signatures"
echo "│   └─ 5_2 [] Setup periodic scanning"
echo "│   └─ 5_3 [] Windows Defender Application Guard"
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
