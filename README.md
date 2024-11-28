# SharpRDPHijack
Sharp RDP Hijack is a proof-of-concept .NET/C# Remote Desktop Protocol (RDP) session hijack utility.

## Background
RDP session hijacking is a post-exploitation technique for taking control of (forcefully) disconnected interactive login sessions. The technique is described in [Mitre ATT&CK T1563.002 - Remote Service Session Hijacking: RDP Hijacking](https://attack.mitre.org/techniques/T1563/002/).

## Notes
- SharpRDPHijack.cs compiles in Visual Studio 2022 under .NET Framework v.4.8 (and likely earlier versions).
- TS/RDP Session query may require privileges depending on the target machine. 
- Session hijacking requires an elevated (administrator) context to connect to another session.
- NT AUTHORITY\SYSTEM context is required to take control of a session unless a target session user's password is known. Without a supplied password, SharpRDPHijack will (attempt to) impersonate NT AUTHORITY\SYSTEM.
- Windows 2019+ Server session hijacking exhibits interesting behavior vs prior OS versions. Upon hijacking a session that is redirected to an activated RDP session, the Windows login screen prompts for the user's password/credential. If redirected to the console session, this redirection is successful and seamless. Leverage the --shadow option with the --console option to attempt to connect to the session via RDP shadowing.
- Several folks have inquired about the function/necessity of this utility when you can do the same thing with tscon.exe or Mimikatz TS.  The goal of writing this POC was to gain a better understanding of what was happening at the Win32 API level (more specifically - Wtsapi32) and to have a simpler option for connecting to other sessions (preferably in C#).  In this implementation, the two functions/methods that do the heavy lifting are [WTSConnectSession](https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsconnectsessiona) and [WTSDisconnectSession](https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsdisconnectsession).  
- Potentially, there is an advantage such that this utility could evade specific detection analytics for tscon.exe + supporting command usage.  Defensive guidance in the linked resources page are useful for addressing abuse of this technique (e.g. logging off disconnected sessions after a timeout period in Group Policy) as well as implementing domain admin login resiliency best practices to minimize domain exposure where non-DA accounts have admin rights on machines also used by DAs. 


## Usage

```
[*] Parameters:
[*] A proof-of-concept Remote Desktop (RDP) session hijack utility
    - For session hijacking, this utility must be run in an elevated context to connect to another session
    - If a password is not specified, NT AUTHORITY\SYSTEM is impersonated
    - For session query, admin privileges or "Remote Desktop Users" group membership is required on the target machine

[*] Parameters:
    --tsquery=<host> : Query a host to identify RDP/TS session information (not required for other switches)
    --session=<ID> : Target session identifier
    --password=<User's Password> : Session password if known (otherwise optional - not required for disconnect switch)
    --console : Redirect session to console session instead of current (active) session
    --shadow : Shadow an active session (experimental)
    --disconnect : Disconnect an active (remote) session

[*] Example Usage 1: Impersonate NT AUTHORITY\SYSTEM to hijack session #6 and redirect to the current session
    SharpRDPHijack.exe --session=6

[*] Example Usage 2: Impersonate NT AUTHORITY\SYSTEM to hijack session #2 and redirect to the console session
    SharpRDPHijack.exe --session=2 --console

[*] Example Usage 3: Hijack Remote Desktop session #4 with knowledge of the logged-on user's password
    SharpRDPHijack.exe --session=4 --password=P@ssw0rd

[*] Example Usage 4: Disconnect active session #3
    SharpRDPHijack.exe --session=3 --disconnect

[*] Example Usage 5: Query the local host for RDP/TS session information
    SharpRDPHijack.exe --tsquery=localhost

[*] Example Usage 6: Shadow active session #3
    SharpRDPHijack.exe --session=3 --shadow

[*] Example Usage 7: Shadow inactive session #2 by redirecting the session to the console
    SharpRDPHijack.exe --session=2 --shadow --console
```

## Other Notable Implementations

- [TScon](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tscon) - Microsoft Terminal Services connection utility (tscon.exe)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) - TS Module

## Ethics

Sharp RDP Hijack is designed to help security professionals perform ethical and legal security assessments and penetration tests. Do not use for nefarious purposes.

## Resources with Defensive Considerations

- [Red Team Experiments | T1076: RDP Hijacking for Lateral Movement with tscon](https://ired.team/offensive-security/lateral-movement/t1076-rdp-hijacking-for-lateral-movement)
- [Kevin Beaumont | RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation](https://doublepulsar.com/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)

## Credits
- [Benjamin Delpy - RDP Session Tradecraft](http://blog.gentilkiwi.com/securite/vol-de-session-rdp)
- [James Forshaw - COM Session Moniker EoP Exploit](https://www.exploit-db.com/exploits/41607)
- [Enable-TSDuplicateToken](https://gallery.technet.microsoft.com/scriptcenter/Enable-TSDuplicateToken-6f485980)
- [PInvoke](https://www.pinvoke.net/)
- [Nick Landers - StealToken Trick](https://twitter.com/monoxgas/status/1109892490566336512)
