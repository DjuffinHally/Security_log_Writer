Tool has to be runas **SystemNT**

Function `<AuthzInstallSecurityEventSource>` adds member to:
* HKEY_LOCAL_MACHINE
  * SYSTEM
    * CurrentControlSet
      * Services
        * EventLog
          * Security

### Created event
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System>
  <Provider Name="Test security audit" /> 
  <EventID Qualifiers="0">5000</EventID> 
  <Level>0</Level> 
  <Task>3</Task> 
  <Keywords>0x8090000000000000</Keywords> 
  <TimeCreated SystemTime="2020-05-18T11:22:13.936457400Z" /> 
  <EventRecordID>46887</EventRecordID> 
  <Channel>Security</Channel> 
  <Computer>DESKTOP-6JJDB2P</Computer> 
  <Security UserID="S-1-5-18" /> 
 </System>
 <EventData>
  <Data>Jay Hamlin</Data> 
  <Data>March 21, 1960</Data> 
 </EventData>
</Event>
```

### Original system security event
```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
  <EventID>4625</EventID> 
  <Version>0</Version> 
  <Level>0</Level> 
  <Task>12544</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8010000000000000</Keywords> 
  <TimeCreated SystemTime="2020-05-18T11:17:44.139246400Z" /> 
  <EventRecordID>46863</EventRecordID> 
  <Correlation ActivityID="{87b3f2aa-296f-0001-44f3-b3876f29d601}" /> 
  <Execution ProcessID="680" ThreadID="9344" /> 
  <Channel>Security</Channel> 
  <Computer>DESKTOP-6JJDB2P</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="SubjectUserSid">S-1-0-0</Data> 
  <Data Name="SubjectUserName">-</Data> 
  <Data Name="SubjectDomainName">-</Data> 
  <Data Name="SubjectLogonId">0x0</Data> 
  <Data Name="TargetUserSid">S-1-0-0</Data> 
  <Data Name="TargetUserName">user-name</Data> 
  <Data Name="TargetDomainName">DOMAIN-NAME</Data> 
  <Data Name="Status">0xc000006d</Data> 
  <Data Name="FailureReason">%%2313</Data> 
  <Data Name="SubStatus">0xc0000064</Data> 
  <Data Name="LogonType">3</Data> 
  <Data Name="LogonProcessName">NtLmSsp</Data> 
  <Data Name="AuthenticationPackageName">NTLM</Data> 
  <Data Name="WorkstationName">WS-NAME</Data> 
  <Data Name="TransmittedServices">-</Data> 
  <Data Name="LmPackageName">-</Data> 
  <Data Name="KeyLength">0</Data> 
  <Data Name="ProcessId">0x0</Data> 
  <Data Name="ProcessName">-</Data> 
  <Data Name="IpAddress">192.168.10.10</Data> 
  <Data Name="IpPort">35114</Data> 
  </EventData>
  </Event>
  ```
### Keyword note
| Keyword			| 	dec				| 	hex				 | bin																  |
| ----------------	| -----------------	| ------------------ | ------------------------------------------------------------------ |
| AuditFailure		| 4503599627370496	| 0x0010000000000000 | 0b0000000000010000000000000000000000000000000000000000000000000000 |
| AuditSuccess		| 9007199254740992	| 0x0020000000000000 | 0b0000000000100000000000000000000000000000000000000000000000000000 |
| CorrelationHint	| 4503599627370496	| 0x0010000000000000 | 0b0000000000010000000000000000000000000000000000000000000000000000 |
| CorrelationHint2	| 18014398509481984	| 0x0040000000000000 | 0b0000000001000000000000000000000000000000000000000000000000000000 |
| EventLogClassic	| 36028797018963968	| 0x0080000000000000 | 0b0000000010000000000000000000000000000000000000000000000000000000 |
| None				| 0					| 0x0000000000000000 | 0b0000000000000000000000000000000000000000000000000000000000000000 |
| ResponseTime		| 281474976710656	| 0x0010000000000000 | 0b0000000000000001000000000000000000000000000000000000000000000000 |
| Sqm				| 2251799813685248	| 0x0080000000000000 | 0b0000000000001000000000000000000000000000000000000000000000000000 |
| WdiContext		| 562949953421312	| 0x0020000000000000 | 0b0000000000000010000000000000000000000000000000000000000000000000 |
| WdiDiagnostic		| 1125899906842624	| 0x0040000000000000 | 0b0000000000000100000000000000000000000000000000000000000000000000 |
