McAfee Removal (Intune Proactive Remediation)
=============================================

This folder contains the detection and remediation scripts used to remove McAfee in device context (SYSTEM), including reboot orchestration for locked-file scenarios.

Files
-----

| File | Purpose |
|------|---------|
| `mcafee_detect.ps1` | Detection script for Intune Proactive Remediations. |
| `mcafee_remediate.ps1` | Remediation/uninstall script with cleanup + reboot handling. |

High-Level Behavior
-------------------

### Detection (`mcafee_detect.ps1`)

- Returns `1` when McAfee is still considered installed:
  - McAfee uninstall registry traces exist, or
  - McAfee file count in known folders is above threshold (`> 10`).
- Returns `0` when compliant/removed.
- Supports reboot marker flow:
  - If `C:\ProgramData\Debloat\McAfeeRemoval.reboot.json` exists and reboot has not occurred yet, detection returns `0` (temporary compliant state).
  - If marker is older than 48 hours, detection returns `1` to re-trigger remediation.
  - If reboot happened after marker creation, marker is cleared and normal detection resumes.

### Remediation (`mcafee_remediate.ps1`)

- Runs cleanup in SYSTEM context and logs to:
  - `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RemoveMcAfee.log`
- Downloads cleanup payloads at runtime:
  - `mcafeeclean.zip`
  - `mccleanup.zip`
- Removes registry traces, AppX/provisioned package traces, known folders, and leftover uninstall entries.
- Uses a state model from `Get-McAfeeStatus`:
  - `0` = clean
  - `1` = installed/significant remnants
  - `2` = residual + lock scenario

Reboot/Retry Strategy
---------------------

When locked files or reboot-required conditions are detected:

1. Remediation schedules reboot at local midnight (`shutdown.exe /r /t <seconds>`).
2. Remediation writes marker:
   - `C:\ProgramData\Debloat\McAfeeRemoval.reboot.json`
3. Remediation registers one-shot startup task:
   - Task name: `McAfeeRemovalPostReboot`
   - Staged script path: `C:\ProgramData\Debloat\mcafee_remediate_postreboot.ps1`
   - Runs with `-PostReboot`
   - Self-deletes after execution.
4. Remediation exits `0` so HealthScripts does not record a hard failure while waiting for reboot.

This is intentional to avoid repeated failed remediation runs caused by file locks that only clear after reboot.

IME/HealthScripts Hardening
---------------------------

The remediation script wraps native tool execution with `Invoke-ProcessQuiet`:

- Captures child process stdout/stderr to temp files.
- Prevents noisy native stderr (for example, transient access denied during locked-file removal) from surfacing as script stderr in IME.
- Logs relevant events to `RemoveMcAfee.log` instead.

This reduces false failure reporting where remediation logic is successful but external command stderr pollutes HealthScripts result details.

Execution Commands
------------------

Run as script files (not dot-sourced):

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\mcafee_detect.ps1
powershell.exe -ExecutionPolicy Bypass -File .\mcafee_remediate.ps1
```

Optional post-reboot mode (normally task-driven):

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\mcafee_remediate.ps1 -PostReboot
```

Operational Notes
-----------------

- Must run in SYSTEM/device context for full cleanup capability.
- Internet access is required during remediation to fetch cleanup ZIPs from GitHub.
- If network blocks GitHub, cleanup tool download will fail and removal may be incomplete.
- Detection threshold is intentionally conservative (`10` files).
- If you need to force re-evaluation immediately, remove marker file and rerun detection/remediation.

Troubleshooting
---------------

Primary logs:

- `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RemoveMcAfee.log`
- `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\HealthScripts.log`

What to check:

1. Final detection state in `RemoveMcAfee.log` (`clean`, `residual`, or `installed`).
2. Presence of marker file and startup task when reboot is pending.
3. HealthScripts policy result for this script:
   - `FirstDetectExitCode`
   - `RemediationExitCode`
   - `RemediationStatus`
   - `RemediationScriptErrorDetails`
