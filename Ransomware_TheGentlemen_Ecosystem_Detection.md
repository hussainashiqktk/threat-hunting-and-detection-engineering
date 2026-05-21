# The Gentlemen Ransomware Ecosystem Lifecycle Detection

This Microsoft Sentinel KQL query provides a unified, consolidated detection rule designed to catch multiple distinct operational phases of **The Gentlemen** Ransomware-as-a-Service (RaaS) toolchain and its associated post-exploitation components (such as the SystemBC proxy framework).

Instead of relying on fragmented, disjointed rules that trigger individual alerts for every minor system change, this query uses independent sub-tables united by a flat conditional union logic. If any single behavior satisfies the criteria, an alert triggers. The resulting telemetry consolidates down to a single row per impacted asset and user, detailing precisely which tactics were identified during the intrusion lifecycle.

## KQL Query

```kql
// 1. Monitor GPO additions or modifications for the scheduled task infrastructure
let GPOModification = 
    SecurityEvent
    | where EventID == 5145
    | where RelativeTargetName has "Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml"
    | extend GPO_GUID = extract(@"\{([A-Fa-f0-9\-]+)\}", 1, RelativeTargetName)
    | project TimeGenerated, Computer, Account, Signal = "GPO_Weaponization", Details = strcat("GPO GUID Modified: ", GPO_GUID);

// 2. Monitor local or remote Scheduled Task creations targeting known ransomware persistence names
let ScheduledTaskCreation =
    SecurityEvent
    | where EventID == 4698
    | extend TaskName = extract(@"<TaskName>(.*)</TaskName>", 1, EventData)
    | where TaskName in~ ("UpdateSystem", "UpdateUser", "DefS", "UpdateGS", "UpdateGS2", "SystemUpdate") or TaskName matches regex @"DefU|UpdateGU"
    | project TimeGenerated, Computer, Account, Signal = "Malicious_Scheduled_Task", Details = strcat("Task Name Created: ", TaskName);

// 3. Monitor Defender tampering and broad path/process exclusions
let DefenderTampering =
    DeviceProcessEvents
    | where ProcessCommandLine has "Set-MpPreference" or ProcessCommandLine has "Add-MpPreference"
    | where ProcessCommandLine has_any ("-DisableRealtimeMonitoring $true", "-ExclusionPath 'C:\\'", "-ExclusionPath 'C:\\Temp'", "-ExclusionProcess")
    | project TimeGenerated, Computer = DeviceName, Account = AccountName, Signal = "Defender_Tampering", Details = ProcessCommandLine;

// 4. Monitor Windows Security Event Log clearing attempts
let LogClearing =
    SecurityEvent
    | where EventID == 1102
    | project TimeGenerated, Computer, Account, Signal = "Log_Clearing", Details = "Audit Log Cleared via wevtutil or API";

// 5. Monitor SystemBC SOCKS5 execution tracking and post-execution discovery validation
let SystemBCProxy =
    DeviceProcessEvents
    | where ProcessCommandLine has_all ("tasklist", "findstr", "socks")
    | project TimeGenerated, Computer = DeviceName, Account = AccountName, Signal = "SystemBC_Proxy_Validation", Details = ProcessCommandLine;

// 6. Monitor core ransomware binary speed, spreading, and deployment argument execution
let RansomwareExecution = 
    DeviceProcessEvents
    | where ProcessCommandLine has "--password" 
    | where ProcessCommandLine has_any ("--spread", "--gpo", "--wipe", "--silent", "--fast", "--superfast", "--ultrafast")
    | project TimeGenerated, Computer = DeviceName, Account = AccountName, Signal = "Gentlemen_Ransomware_Execution", Details = ProcessCommandLine;

// --- Consolidate all signals into a single unified stream ---
union GPOModification, ScheduledTaskCreation, DefenderTampering, LogClearing, SystemBCProxy, RansomwareExecution
| summarize 
    FirstSeen = min(TimeGenerated), 
    LastSeen = max(TimeGenerated), 
    IncidentCount = count(),
    DetectedTactics = make_set(Signal),
    EvidenceDetails = make_set(Details) 
    by Computer, Account

```
