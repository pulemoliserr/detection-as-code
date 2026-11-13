# Rule & ATT&CK coverage

| Rule | Type | Level | Log source | ATT&CK techniques | File |
|---|---|---|---|---|---|
| Linux Local User Account Created | Detection | medium | linux / process_creation | T1136.001 | [lnx_new_user_created.yml](../rules/linux/lnx_new_user_created.yml) |
| Linux SSH Failed Authentication | Detection | low | linux / auth | T1110.001 | [lnx_ssh_bruteforce.yml](../rules/linux/lnx_ssh_bruteforce.yml) |
| Linux SSH Brute Force from a Single Source | Correlation | high | (correlates linux_ssh_failed_auth) | T1110.001 | [lnx_ssh_bruteforce.yml](../rules/linux/lnx_ssh_bruteforce.yml) |
| Linux Permissions Made World-Writable | Detection | medium | linux / process_creation | T1222.002 | [lnx_world_writable_permissions.yml](../rules/linux/lnx_world_writable_permissions.yml) |
| Web Path Traversal Attempt | Detection | high | webserver | T1190 | [web_path_traversal.yml](../rules/web/web_path_traversal.yml) |
| Web SQL Injection Attempt | Detection | high | webserver | T1190 | [web_sql_injection_attempt.yml](../rules/web/web_sql_injection_attempt.yml) |
| Windows Failed Logon | Detection | low | windows / security | T1110 | [win_failed_logon_bruteforce.yml](../rules/windows/win_failed_logon_bruteforce.yml) |
| Windows Logon Brute Force from a Single Source | Correlation | high | (correlates windows_failed_logon) | T1110 | [win_failed_logon_bruteforce.yml](../rules/windows/win_failed_logon_bruteforce.yml) |
| LSASS Memory Dump via ProcDump or Comsvcs | Detection | critical | windows / process_creation | T1003.001 | [win_lsass_memory_dump.yml](../rules/windows/win_lsass_memory_dump.yml) |
| Office Application Spawning a Shell or Script Host | Detection | high | windows / process_creation | T1566.001, T1204.002 | [win_office_spawns_shell.yml](../rules/windows/win_office_spawns_shell.yml) |
| PowerShell Download Cradle | Detection | medium | windows / process_creation | T1059.001, T1105 | [win_powershell_download_cradle.yml](../rules/windows/win_powershell_download_cradle.yml) |
| PowerShell Encoded Command Execution | Detection | high | windows / process_creation | T1059.001, T1027 | [win_powershell_encoded_command.yml](../rules/windows/win_powershell_encoded_command.yml) |
| Scheduled Task Created from a Suspicious Location | Detection | medium | windows / process_creation | T1053.005 | [win_schtasks_suspicious_create.yml](../rules/windows/win_schtasks_suspicious_create.yml) |
| Windows Security Event Log Cleared | Detection | high | windows / security | T1070.001 | [win_security_log_cleared.yml](../rules/windows/win_security_log_cleared.yml) |
| Shadow Copy or Backup Catalog Deletion | Detection | critical | windows / process_creation | T1490 | [win_shadow_copy_deletion.yml](../rules/windows/win_shadow_copy_deletion.yml) |
| User Added to Local Administrators Group | Detection | medium | windows / security | T1098 | [win_user_added_to_admins.yml](../rules/windows/win_user_added_to_admins.yml) |

## Coverage by tactic

| Tactic | Techniques covered |
|---|---|
| Initial Access | T1190, T1204.002, T1566.001 |
| Execution | T1027, T1053.005, T1059.001, T1105, T1204.002, T1566.001 |
| Persistence | T1053.005, T1098, T1136.001 |
| Privilege Escalation | T1098 |
| Defense Evasion | T1027, T1059.001, T1070.001, T1222.002 |
| Credential Access | T1003.001, T1110, T1110.001 |
| Command And Control | T1059.001, T1105 |
| Impact | T1490 |

**16 rules · 15 ATT&CK techniques**
