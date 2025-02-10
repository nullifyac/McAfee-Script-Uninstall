McAfee Removal Script
======================

This repository contains PowerShell scripts and supporting files to detect, remove, and optionally prompt for a reboot when uninstalling McAfee products in a Windows environment. These are designed primarily for use with Microsoft Intune or SCCM, but they can be adapted to other deployment tools.

Contents
--------

- **mcafee_detect.ps1**  
  A detection script that checks whether McAfee is currently installed.  
  - Exits **1** if McAfee is found in the registry or on disk.  
  - Exits **0** if McAfee is not detected.  
  - Additional logic: If QcShm.exe is running, the script still exits **0** while logging that a reboot is required.

- **mcafee_remediate.ps1**  
  The remediation (uninstall) script that:
  1. Checks if McAfee is present (if not, it skips further actions).
  2. If present, downloads and runs the cleanup tools (*mcafeeclean.zip*, *mccleanup.zip*) and removes leftover McAfee registry entries, folders, etc.
  3. Displays an indefinite “Snooze or Restart” pop-up if a reboot is needed (requires *ServiceUI.exe* when running as SYSTEM).
  4. If no user is logged on (or *ServiceUI.exe* is missing), forces a reboot by default.

- **mcafeeclean.zip**, **mccleanup.zip**  
  ZIP files containing McAfee cleanup tools (each includes *Mccleanup.exe*) for removing various McAfee components.

- **ServiceUI.exe**  
  A small executable (from Microsoft Deployment Toolkit) that allows a SYSTEM process to display an interactive window on the logged-on user’s desktop, enabling the indefinite “Yes=Restart / No=Snooze 5 minutes” prompt for non-admin users.

How It Works
------------

1. **Detection**  
   - In Intune or SCCM, run **mcafee_detect.ps1**.  
   - If it exits **1**, McAfee is present; if it exits **0**, McAfee is not present.  
   - If only *QcShm.exe* remains, the script considers McAfee uninstalled (exit 0) but notes a reboot is needed.

2. **Remediation / Removal**  
   - When McAfee is present, run **mcafee_remediate.ps1**:
     1. (Optionally) checks if McAfee is installed.
     2. Downloads *mcafeeclean.zip*, *mccleanup.zip*, and *ServiceUI.exe* if needed.
     3. Extracts and runs the McAfee cleanup executables.
     4. Cleans up leftover registry keys, folders, etc.
     5. If remnants remain needing a reboot, displays an indefinite “Yes=Restart / No=Snooze 5 minutes” prompt via *ServiceUI.exe*.
        - If no user is logged on, a forced reboot occurs automatically.

Deployment Scenarios
--------------------

**Intune (Proactive Remediation or Script Deployment)**

- Upload **mcafee_detect.ps1** as the Detection Script.  
- Upload **mcafee_remediate.ps1** as the Remediation Script.  
- Both run under SYSTEM by default:
  - If mcafee_detect.ps1 exits 1, Intune triggers mcafee_remediate.ps1.
- Reboot logic:
  - If a user is logged on, *ServiceUI.exe* displays the indefinite snooze/restart prompt.
  - Otherwise, the script forces a reboot.

**SCCM (Configuration Manager)**

- Use **mcafee_detect.ps1** as the application/package detection method:
  - Exit code 0 => not installed, 1 => installed.
- Use **mcafee_remediate.ps1** as the uninstall program in the SCCM deployment.
- SCCM can handle device reboots, or let the script force a reboot.

Files
-----

| File              | Description                                                                                                                           |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| mcafee_detect.ps1 | Checks registry + known McAfee folders. Exits 1 if found, 0 if not. If only QcShm.exe remains, exits 0 while noting a reboot is needed. |
| mcafee_remediate.ps1 | Full removal script (runs as SYSTEM) that downloads mcafeeclean.zip, mccleanup.zip, ServiceUI.exe, cleans up McAfee, and prompts for reboot. |
| mcafeeclean.zip   | McAfee cleanup tool #1 (includes Mccleanup.exe).                                                                                     |
| mccleanup.zip     | McAfee cleanup tool #2 (includes Mccleanup.exe).                                                                                     |
| ServiceUI.exe     | Utility that displays a user prompt from a SYSTEM context, allowing indefinite “snooze or restart.”                                  |

Notes & Tips
------------

1. **User vs. SYSTEM Context**  
   - SCCM/Intune typically run scripts as SYSTEM. *ServiceUI.exe* is used to inject a prompt into the user’s session.

2. **Licensing**  
   - *ServiceUI.exe* is from Microsoft Deployment Toolkit (MDT). Only this single .exe is needed. Check MDT’s licensing terms for usage.

3. **QcShm.exe**  
   - If QcShm.exe remains in memory, a reboot is needed. The detection script logs this but still exits 0, treating McAfee as uninstalled.
   - QcShm.exe is from the "cleaning" process of the uninstall and residual files/traces may be left on the system until its rebooted.

4. **Troubleshooting**  
   - Check `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RemoveMcAfee.log` (Intune) or SCCM logs for script output.
   - If the indefinite prompt never appears, ensure a user is logged on, *ServiceUI.exe* is present, and your environment allows interactive dialogs from SYSTEM.

Example Flows
-------------

1. **No McAfee Found**  
   - Detection script exits 0; no remediation triggered.

2. **McAfee Found, No User Logged On**  
   - Detection script exits 1.
   - Remediation script removes McAfee, finds no user => forced reboot.

3. **McAfee Found, User Logged On**  
   - Detection script exits 1.
   - Remediation script removes McAfee, sees leftover references => uses *ServiceUI.exe* => user sees indefinite “Yes=Restart / No=Snooze 5 minutes” prompt.

Contributors
------------

Me, ClaudeAI & andrew-s-taylor
