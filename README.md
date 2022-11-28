# Windows 10 ITC8080 Hardening operating systems and services

Authors: Joosep Parts, Helena Jäe, Karl Tamberg, Artur Niki, Adi ??

The following documentation covers how Windows 10 hardening was achived and have we have audited it to cover 80% most typical cases. More detaild explenation of specific hardening steps are commented inline of script itself.

Target machine is running Windows 10 (more specifically 21H1).

In general general `win-10-hardening-script.cmd` is compiled using best practices from official and unofficial sources among official govement issued reccomendations:
1. [Hardening Microsoft Windows 10 version 21H1 Workstations](https://www.cyber.gov.au/acsc/view-all-content/publications/hardening-microsoft-windows-10-version-21h1-workstations) - AU gov.
2. [Guidance for hardening Microsoft Windows 10 Enterprise (ITSP.70.012)](https://cyber.gc.ca/en/guidance/guidance-hardening-microsoft-windows-10-enterprise-itsp70012) - Cancadian gov.
3. [Device Security Guidance](https://www.ncsc.gov.uk/collection/device-security-guidance/platform-guides/windows) - UK gov.
4. [CIS Critical Security Controls v7.1 Microsoft Windows 10 Cyber Hygiene Guide](https://www.cisecurity.org/insights/white-papers/cis-controls-microsoft-windows-10-cyber-hygiene-guide) - CIS.

## Hardening script
https://github.com/Nurech/win-10-hardening-script/blob/master/win-10-hardening-script.cmd
Features an executable cmd script which utilizes `powershell` to run actions as
```
win-10-hardening-script.cmd
     ├─ File associations
     ├─ Enable Network protection
     ├─ Windows Defender
     │   └─ Updates signatures
     │   └─ Setup periodic scanning
     │   └─ Windows Defender Application Guard
     ├─ Harden MS Office
```
