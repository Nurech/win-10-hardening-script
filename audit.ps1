$1_1 = "False"
$2 = "False"
$3 = "False"
$4 = "False"
$5 = "False"
$PUAProtection = "False"
$DeviceGuard = "False"
$6 = "False"
$GenOsHard = "False"
$7_1 = "False"
$7_2 = "False"
$7_3 = "False"
$7_4 = "False"
$7_5 = "False"
$7_6 = "False"
$7_7 = "False"
$7_8 = "False"
$7_9 = "False"
$7_10 = "False"
$8 = "False"
$9 = "False"
$10 = "False"
$11 = "False"
$12 = "False"
$13 = "False"
$14 = "False"
$14_1 = "False"
$15 = "False"
$16 = "False"
$17 = "False"
$18 = "False"
$19 = "False"
$20 = "False"


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
    testHardenMSOffice
    testGeneralOSHardening
    testHardenlsass
    testDisabletheClickOnce
    testBiometrics
    testDisableweakTLS
    testInternetBrowserSettings
    testWindows10Privacy
    testDisablelocationdata
    testEnlargeWindowsEvent
    testEnableWindowsEvent
    testDetailedLogging
    testUninstallunwantedprograms
    testEdgehardening
    testConfigureGoogleChrome
    testEnforcedevicedriver
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

    $res2 = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\' -Name EnableVirtualizationBasedSecurity 

    If ($res2 -eq "1") {
        $script:DeviceGuard = "True"
    } Else {
        $script:DeviceGuard = "False"
    }

    If ($PUAProtection -eq "True" -And $DeviceGuard -eq "True") {
        $script:5 = "True"
    }

}

function testHardenMSOffice() {
    $res = Get-ItemPropertyValue -Path 'HKCU:SOFTWARE\Microsoft\Office\Common\Security' -Name DisableAllActiveX
    If ($res -eq "1") {
        $script:6 = "True"
    } Else {
        $script:6 = "False"
    }
}

function testGeneralOSHardening() {
    $res7_1 = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' -Name AddPrinterDrivers
    If ($res7_1 -eq "1") {
        $script:7_1 = "True"
    } Else {
        $script:7_1 = "False"
    }

    $res7_2 = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name SupportedEncryptionTypes
    If ($res7_2 -eq "2147483640") {
        $script:7_2 = "True"
    } Else {
        $script:7_2 = "False"
    }

    $res7_3 = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name DisableIPSourceRouting
    If ($res7_3 -eq "2") {
        $script:7_3 = "True"
    } Else {
        $script:7_3 = "False"
    }

    $res7_4 = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name NTLMMinServerSec
    If ($res7_4 -eq "537395200") {
        $script:7_4 = "True"
    } Else {
        $script:7_4 = "False"
    }

    $res7_5 = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' -Name NoGPOListChanges
    If ($res7_5 -eq "0") {
        $script:7_5 = "True"
    } Else {
        $script:7_5 = "False"
    }

    $res7_6 = Get-ItemPropertyValue -Path 'HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters' -Name RequireSecuritySignature
    If ($res7_6 -eq "1") {
        $script:7_6 = "True"
    } Else {
        $script:7_6 = "False"
    }

    $res7_7 = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel
    If ($res7_7 -eq "5") {
        $script:7_7 = "True"
    } Else {
        $script:7_7 = "False"
    }

    $res7_8 = Get-ItemPropertyValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name Enabled
    If ($res7_8 -eq "0") {
        $script:7_8 = "True"
    } Else {
        $script:7_8 = "False"
    }

    $res7_9 = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name DODownloadMode
    If ($res7_9 -eq "0") {
        $script:7_9 = "True"
    } Else {
        $script:7_9 = "False"
    }

    $res7_10 = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fAllowToGetHelp
    If ($res7_10 -eq "0") {
        $script:7_10 = "True"
    } Else {
        $script:7_10 = "False"
    }

    If($7_1 -eq "1" -And $7_2 -eq "1" -And $7_3 -eq "1" -And $7_4 -eq "1" -And $7_5 -eq "1" -And $7_6 -eq "1" -And $7_7 -eq "1" -And $7_8 -eq "1" -And $7_9 -eq "1" -And $7_10 -eq "1") {
        $script:GenOsHard = "True"
    }
}

function testHardenlsass() {
    $res = Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe' -Name AuditLevel
    If ($res -eq "00000008") {
        $script:8 = "True"
    } Else {
        $script:8 = "False"
    }
}

function testDisabletheClickOnce() {
    $res = Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel' -Name MyComputer
    If ($res -eq "Disabled") {
        $script:9 = "True"
    } Else {
        $script:9 = "False"
    }
}

function testEnableWindowsFirewall() {
    $res = Get-NetFirewallRule | Where-Object -Property Name -EQ 'Block appvlp.exe netconns'
    If ($res.Enabled -eq "True") {
        $script:10 = "True"
    } Else {
        $script:10 = "False"
    }
}

function testBiometrics() {
    $res = Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' -Name EnhancedAntiSpoofing
    If ($res -eq "1") {
        $script:11 = "True"
    } Else {
        $script:11 = "False"
    }
}

function testDisableweakTLS() {
    $res = Get-ItemPropertyValue -Path 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128' -Name Enabled
    If ($res -eq "0xffffffff") {
        $script:12 = "True"
    } Else {
        $script:12 = "False"
    }
}

function testInternetBrowserSettings() {
    $res = Get-ItemPropertyValue -Path 'HKCU:SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name EnabledV9
    If ($res -eq "1") {
        $script:13 = "True"
    } Else {
        $script:13 = "False"
    }
}

function testWindows10Privacy() {
    $res = Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name LimitEnhancedDiagnosticDataWindowsAnalytics
    If ($res -eq "1") {
        $script:14 = "True"
    } Else {
        $script:14 = "False"
    }
}

function testDisablelocationdata() {
    $res = Get-ItemPropertyValue -Path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore' -Name Location
    If ($res -eq "Deny") {
        $script:14_1 = "True"
    } Else {
        $script:14_1 = "False"
    }
}


function testEnlargeWindowsEvent() {
    $res = get-eventlog -list -ComputerName $env:computername| Where-Object {$_.Log -eq 'Security' }| select Log, MaximumKilobytes, @{n="Server";e={$env:computername}}
    If ($res.MaximumKilobytes -eq "1024000") {
        $script:15 = "True"
    } Else {
        $script:15 = "False"
    }
}


function testDetailedLogging() {
    $res = auditpol /get /subcategory:"Security Group Management"
    If ($res -like "*Security Group Management*" -And $res -like "*Success*") {
        $script:16 = "True"
    } Else {
        $script:16 = "False"
    }
}

function testUninstallunwantedprograms() {
    $res = powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingWeather'}
    $res1 = powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxApp'}
    If ($res -eq $null -And $res1 -eq $null) {
        $script:17 = "True"
    } Else {
        $script:17 = "False"
    }
}

function testEdgehardening() {
    $res = Get-ItemPropertyValue -Path 'HKLM:Software\Policies\Microsoft\Edge' -Name BackgroundModeEnabled
    If ($res -eq "0") {
        $script:18 = "True"
    } Else {
        $script:18 = "False"
    }
}

function testConfigureGoogleChrome() {
    $res = Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Policies\Google\Chrome' -Name AllowCrossOriginAuthPrompt
    If ($res -eq "0") {
        $script:19 = "True"
    } Else {
        $script:19 = "False"
    }
}

function testEnforcedevicedriver() {
    $res = Bcdedit.exe | findstr "systemroot"
    If ($res -like "*OFF*") {
        $script:20 = "True"
    } Else {
        $script:20 = "False"
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
echo "├─ 6 [$6] Harden MS Office"
echo "├─ 7 [$GenOsHard] General OS Hardening"
echo "│   └─ 7_1 [$7_1] Enforce the Administrator role on common attack points"
echo "│   └─ 7_2 [$7_2] Prevent Kerberos from using DES or RC4"
echo "│   └─ 7_3 [$7_3] TCPIP parameters"
echo "│   └─ 7_4 [$7_4] Shared access (LSA)"
echo "│   └─ 7_5 [$7_5] Group Policy"
echo "│   └─ 7_6 [$7_6] Enable SMB/LDAP Signing"
echo "│   └─ 7_7 [$7_7] Enforce NTLMv2 and LM authentication"
echo "│   └─ 7_8 [$7_8] Disable script.exe, DLL Hijacking, IPv6, WinRM Service, NetBIOS, AutoRun"
echo "│   └─ 7_9 [$7_9] Windows Update Settings"
echo "│   └─ 7_10 [$7_10] Windows Remote Access Settings"
echo "├─ 8 [$8] Harden lsass to help protect against credential dumping"
echo "├─ 9 [$9] Disable the ClickOnce trust prompt"
echo "├─ 10 [$10] Enable Windows Firewall and configure some advanced options + logging"
echo "├─ 11 [$11] Biometrics"
echo "├─ 12 [$12] Disable weak TLS/SSL ciphers and protocols"
echo "├─ 13 [$13] Enable and Configure Internet Browser Settings"
echo "├─ 14 [$14] Windows 10 Privacy Settings"
echo "│   └─ 14_1 [$14_1] Disable location data, Windows GameDVR, consumer experience"
echo "├─ 15 [$15] Enlarge Windows Event Security Log Size"
echo "├─ 16 [$16] Enable Windows Event Detailed Logging"
echo "├─ 17 [$17] Uninstall unwanted programs"
echo "├─ 18 [$18] Edge hardening"
echo "├─ 19 [$19] Enable and Configure Google Chrome Internet Browser Settings"
echo "├─ 20 [$20] Enforce device driver signing"
echo ""
pause
