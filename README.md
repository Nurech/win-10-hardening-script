
# Windows 10 ITC8080 Hardening operating systems and services

Authors: Joosep Parts, Helena Jäe, Karl Tamberg, Artur Nikitchuk, Aaditya Parashar

The following documentation covers how Windows 10 hardening was achieved and how have we have audited it to cover 80% of most typical cases. More detailed explanations of specific hardening steps are commented in line of the script itself.

The target machine is running Windows 10 (more specifically, 21H1). The target audience is typical consumers with a fresh install of Windows 10 running for the first time.
Tested and developed on [Windows 10 image from Microsoft](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/) running on VirtualBox (and VM Ware).

In general general `hardening.cmd` is compiled using best practices from official and unofficial sources among official government-issued recommendations:
1. [Hardening Microsoft Windows 10 version 21H1 Workstations](https://www.cyber.gov.au/acsc/view-all-content/publications/hardening-microsoft-windows-10-version-21h1-workstations) - AU gov.
2. [Guidance for hardening Microsoft Windows 10 Enterprise (ITSP.70.012)](https://cyber.gc.ca/en/guidance/guidance-hardening-microsoft-windows-10-enterprise-itsp70012) - Canadian gov.
3. [Device Security Guidance](https://www.ncsc.gov.uk/collection/device-security-guidance/platform-guides/windows) - UK gov.
4. [CIS Critical Security Controls v7.1 Microsoft Windows 10 Cyber Hygiene Guide](https://www.cisecurity.org/insights/white-papers/cis-controls-microsoft-windows-10-cyber-hygiene-guide) - CIS.

## Order of actions
1. We first run `audit.ps1`, giving us feedback on Windows 10 status in `true/false statements`. 
2. We can then select option to harden audited points.
3. We afterwards we can then run `audit.ps1` again to confirm the processes made by `hardening.cmd`.

## Hardening script
[https://github.com/Nurech/win-10-hardening-script/blob/master/win-10-hardening-script.cmd](https://github.com/Nurech/win-10-hardening-script/blob/master/hardening.cmd)
Features an executable cmd script that utilizes `PowerShell` to run the following actions:
```
hardening.cmd
     ├─ 1 Create a restore point
     │   └─ 1_1 Block remote commands
     ├─ 2 File associations
     ├─ 3 Enable Network protection
     ├─ 4 Enable exploit protection     
     ├─ 5 Windows Defender
     │   └─ 5_1 Potentially Unwanted Applications
     │   └─ 5_2 Windows Defender Application Guard
     ├─ 6 Harden MS Office
     ├─ 7 General OS hardening
     │   └─ 7_1 Enforce the Administrator role on common attack points       
     │   └─ 7_2 Prevent Kerberos from using DES or RC4    
     │   └─ 7_3 TCPIP parameters    
     │   └─ 7_4 Shared access (LSA)
     │   └─ 7_5 Group Policy
     │   └─ 7_6 Enable SMB/LDAP Signing
     │   └─ 7_7 Enforce NTLMv2 and LM authentication
     │   └─ 7_8 Disable script.exe, DLL Hijacking, IPv6, WinRM Service, NetBIOS, AutoRun
     │   └─ 7_9 Windows Update Settings
     │   └─ 7_10 Windows Remote Access Settings 
     ├─ 8 Harden lsass to help protect against credential dumping
     ├─ 9 Disable the ClickOnce trust prompt
     ├─ 10 Enable Windows Firewall and configure some advanced options + logging
     ├─ 11 Biometrics
     ├─ 12 Disable weak TLS/SSL ciphers and protocols
     ├─ 13 Enable and Configure Internet Browser Settings
     ├─ 14 Windows 10 Privacy Settings
     │   └─ 14_1 Disable location data, Windows GameDVR, consumer experience       
     ├─ 15 Enlarge Windows Event Security Log Size
     ├─ 16 Enable Windows Event Detailed Logging
     ├─ 17 Uninstall unwanted programs
     ├─ 18 Edge hardening
     ├─ 19 Enable and Configure Google Chrome Internet Browser Settings
     ├─ 20 Enforce device driver signing       
```
