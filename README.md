
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
1. We first run `audit.ps1`, giving us feedback on Windows 10 status in `true/false statements. 
2. We can then select option to harden audited points.
3. We afterwards we can then run `audit.cmd` again to confirm the processes made by `hardening.cmd`.

## Hardening script
[https://github.com/Nurech/win-10-hardening-script/blob/master/win-10-hardening-script.cmd](https://github.com/Nurech/win-10-hardening-script/blob/master/hardening.cmd)
Features an executable cmd script that utilizes `PowerShell` to run the following actions:
```
hardening.cmd
     ├─ 1. Create a restore point
     ├─ 2. File associations
     ├─ 3. Enable Network protection
     ├─ 4. Enable exploit protection     
     ├─ 5. Windows Defender
     │   └─ Updates signatures
     │   └─ Setup periodic scanning
     │   └─ Windows Defender Application Guard
     ├─ Harden MS Office
     │   └─ Word, Excel, Powerpoint  
     ├─ General OS hardening
     │   └─ Enforce the Administrator role on common attack points       
     │   └─ Prevent Kerberos from using DES or RC4    
     │   └─ TCPIP parameters    
     │   └─ Shared access (LSA)
     │   └─ Group Policy
     │   └─ Enable SMB/LDAP Signing
     │   └─ Enforce NTLMv2 and LM authentication
     │   └─ Disable script.exe, DLL Hijacking, IPv6, WinRM Service, NetBIOS, AutoRun
     │   └─ Windows Update Settings
     │   └─ Windows Remote Access Settings 
     ├─ Harden lsass to help protect against credential dumping
     ├─ Disable the ClickOnce trust prompt
     ├─ Enable Windows Firewall and configure some advanced options + logging
     ├─ Biometrics
     ├─ Disable weak TLS/SSL ciphers and protocols
     ├─ Enable and Configure Internet Browser Settings
     ├─ Windows 10 Privacy Settings
     │   └─ Disable location data, Windows GameDVR, consumer experience       
     ├─ Enlarge Windows Event Security Log Size
     ├─ Enable Windows Event Detailed Logging
     ├─ Uninstall unwanted programs
     ├─ Edge hardening
     ├─ Enable and Configure Google Chrome Internet Browser Settings
     ├─ Enforce device driver signing       
```
