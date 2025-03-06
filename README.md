McAfee Removal Script
======================

This repository contains PowerShell scripts and supporting files to detect, remove, and optionally schedule a reboot when uninstalling McAfee products in a Windows environment. These scripts are designed primarily for use with Microsoft Intune or SCCM, but they can be adapted to other deployment tools.

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
  3. **Reboot Logic:**  
     - After cleanup, if any residual McAfee files remain (for example, a few files locked by the QcShm.exe process), the script schedules a reboot at local midnight.
     - The script calculates the time remaining until midnight (based on the local machine’s time) and uses `shutdown.exe` with that delay to schedule the reboot.
     - If no residual files are found (or if McAfee is completely removed), the script exits normally without scheduling a reboot.
  4. If remnants remain beyond the acceptable threshold (indicating McAfee is still installed), the script exits with code **1** so that remediation will be re‑attempted.

- **mcafeeclean.zip**, **mccleanup.zip**  
  ZIP files containing McAfee cleanup tools (each includes *Mccleanup.exe*) for removing various McAfee components.

How It Works
------------

1. **Detection**  
   - In Intune or SCCM, run **mcafee_detect.ps1**.  
   - If it exits **1**, McAfee is present; if it exits **0**, McAfee is not present.  
   - If only QcShm.exe remains, the script considers McAfee uninstalled (exit 0) but notes a reboot is needed.

2. **Remediation / Removal**  
   - When McAfee is present, run **mcafee_remediate.ps1**:
     1. checks if McAfee is installed.
     2. Downloads *mcafeeclean.zip*, *mccleanup.zip*.
     3. Extracts and runs the McAfee cleanup executables.
     4. Cleans up leftover registry keys, folders, etc.
     5. **Reboot Scheduling:**  
        - After cleanup, the script re‑checks the system.
        - If only residual files remain (e.g. a few locked files by QcShm.exe), it calculates how many seconds remain until local midnight and then schedules a reboot using:
          ```
          shutdown.exe /r /t <seconds>
          ```
          This ensures the system reboots at midnight.
        - The reboot is automatically scheduled without further user interaction.
     6. If significant remnants still exist after remediation, the script exits with **1** so that remediation is re‑attempted.

Deployment Scenarios
--------------------

**Intune (Proactive Remediation or Script Deployment)**

- Upload **mcafee_detect.ps1** as the Detection Script.  
- Upload **mcafee_remediate.ps1** as the Remediation Script.  
- Both run under SYSTEM by default:
  - If mcafee_detect.ps1 exits 1, Intune triggers mcafee_remediate.ps1.
- Reboot logic:
  - If residual files are detected (e.g. due to QcShm.exe locking a few files), the script schedules a reboot at local midnight.

**SCCM (Configuration Manager)**

- Use **mcafee_detect.ps1** as the application/package detection method:
  - Exit code 0 => not installed, 1 => installed.
- Use **mcafee_remediate.ps1** as the uninstall program in the SCCM deployment.
- SCCM can handle device reboots, or let the script schedule a reboot at midnight.

Files
-----

| File                 | Description                                                                                                                                    |
|----------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| mcafee_detect.ps1    | Checks registry and known McAfee folders. Exits 1 if McAfee is found, 0 if not.                                                                |
| mcafee_remediate.ps1 | Full removal script (runs as SYSTEM) that downloads mcafeeclean.zip and mccleanup.zip, cleans up McAfee, and schedules a reboot if needed.     |
| mcafeeclean.zip      | McAfee cleanup tool #1 (includes Mccleanup.exe).                                                                                               |
| mccleanup.zip        | McAfee cleanup tool #2 (includes Mccleanup.exe).                                                                                               |

Notes & Tips
------------

1. **User vs. SYSTEM Context**  
   - Script is made to run in the SYSTEM context.
2. **QcShm.exe**  
   - If QcShm.exe is running, a reboot is required to clear locked residual files. The detection script logs this scenario and treats McAfee as uninstalled (exit 0) even though a reboot is scheduled.
3. **Troubleshooting**  
   - Check C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RemoveMcAfee.log (or SCCM logs) for detailed script output and status.

Example Flows
-------------

1. **No McAfee Found**  
   - Detection script exits 0; no remediation is triggered.

2. **McAfee Found**  
   - Detection script exits 1.
   - Remediation script removes McAfee and schedules a reboot at midnight.

3. **McAfee Found, Residual Files Remain**  
   - Detection script exits 1.
   - Remediation script removes McAfee, detects residual locked files, and schedules a reboot at local midnight.

Contributors
------------

nullifyac & wUEZRs
