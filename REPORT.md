# Report

Wrote this report aiming to perform a complete investigation based on threats that happened in the Wazuh SOC Analyst playlist.

---

## Findings (What did i find)

- **System Discovery Activities (MITRE T1033 / T1016 / T1087 / T1018):** Execution of standard enumeration commands across both Windows and Linux endpoints (`whoami`, `ipconfig /all`, `net user`, `net localgroup administrators`, `ip a`).
- **Default Accounts and Account Manipulation (MITRE T1078.001 / T1098):** The default disabled local `Guest/Convidado` account was enabled (`/active:yes`) and assigned a new password.

![Captura de ecrã 2026-09-02, às 21.06.26.png](images/Captura_de_ecra_2026-09-02_as_21.06.26.png)

![Captura de ecrã 2026-09-02, às 21.08.40.png](images/Captura_de_ecra_2026-09-02_as_21.08.40.png)

![Captura de ecrã 2026-09-02, às 21.18.20.png](images/Captura_de_ecra_2026-09-02_as_21.18.20.png)

![Captura de ecrã 2026-09-02, às 21.18.26.png](images/Captura_de_ecra_2026-09-02_as_21.18.26.png)

- **Local Account Creation, Privilege Escalation & Account Access Removal (MITRE T1136.001 / T1098 / T1531):** A user account (`student1`) was created, added to the local `Administrators` group, and subsequently deleted.

![Captura de ecrã 2026-09-02, às 21.37.33.png](images/Captura_de_ecra_2026-09-02_as_21.37.33.png)

- **Sensitive File Access & Local Data Staging (MITRE T1552.001 / T1074.001):** Inspection of `/etc/passwd` on the Linux target and redirection of its content to a staging file (`/tmp/loot.txt`).
    - Direct command execution on Linux bypassed process telemetry due to lack of `auditd` system call monitoring. However, the resulting artifact was captured as a file addition event via File Integrity Monitoring (FIM Rule 554).
    
    ![Captura de ecrã 2026-09-03, às 11.20.16.png](images/Captura_de_ecra_2026-09-03_as_11.20.16.png)
    

![Captura de ecrã 2026-09-03, às 11.20.23.png](images/Captura_de_ecra_2026-09-03_as_11.20.23.png)

- **SSH Brute-Force and Password Guessing (MITRE T1110.001):** Interactive SSH session via account `diogofilipe` followed by multiple failed password attempts.

![Captura de ecrã 2026-09-02, às 22.18.14.png](images/Captura_de_ecra_2026-09-02_as_22.18.14.png)

![Captura de ecrã 2026-09-02, às 22.18.21.png](images/Captura_de_ecra_2026-09-02_as_22.18.21.png)

- **Detection Controls & Active Response Validation:** Implementation of File Integrity Monitoring (**FIM**), custom detection rules (`local_rules.xml`), and dynamic containment via Wazuh Active Response (`firewall-drop` via `iptables`).
    - **FIM**: verified real-time integrity alerts for file creation, modification, and deletion across monitored directories on both Windows and Linux endpoints.
        - Windows:
        
        ![Captura de ecrã 2026-09-02, às 22.51.12.png](images/Captura_de_ecra_2026-09-02_as_22.51.12.png)
        
        - Linux:
    
    ![Captura de ecrã 2026-09-02, às 22.52.03.png](images/Captura_de_ecra_2026-09-02_as_22.52.03.png)
    

## Investigation Summary (What happened)

### Who (Who was involved?)

- **Source Host / Operator:** Windows Endpoint (`192.168.158.131` / `Bob`).
- **Target Systems:** Ubuntu Server (`192.168.158.130`).
- **Accounts Involved / Manipulated:**
    - `Guest` (Reactivated and modified).
    - `student1` (Temporary local administrator created and deleted).
    - `diogofilipe` (SSH Brute-Force).

### What (What happened?)

1. **Windows Discovery & Privilege Abuse:** Native administrative utilities were executed to map network and user configurations. The `Guest` account was enabled, and a secondary administrator account (`student1`) was created, added to administrators group and later deleted.
2. **Lateral Movement & Credential Access (Linux):** SSH traffic originated from the Windows host to the Linux target (`192.168.158.130`). After that an interactive session was established as `diogofilipe`, extracting `/etc/passwd` to `/tmp/loot.txt`.
3. **SSH Brute-Force and password guessing**: Established a SSH connection to `diogofilipe` followed by failing the password three consecutive times within two minutes.
4. **Detection Engineering & Automated Mitigation:**
    - Custom rule deployed to alert on `Guest`/`Convidado` account activation.
    
    ![Captura de ecrã 2026-09-03, às 14.18.05.png](images/Captura_de_ecra_2026-09-03_as_14.18.05.png)
    
    - Timeframe-based correlation rule created for SSH brute-force (3 failures in 120s using `<if_matched_sid>5710</if_matched_sid>` and `<same_source_ip />`).
    
    ![Captura de ecrã 2026-09-03, às 14.19.16.png](images/Captura_de_ecra_2026-09-03_as_14.19.16.png)
    
    - Active Response triggered `firewall-drop`, applying dynamic `iptables` drop rules against the offensive IP.
    
    ![Captura de ecrã 2026-09-03, às 14.25.16.png](images/Captura_de_ecra_2026-09-03_as_14.25.16.png)
    
    ![Captura de ecrã 2026-09-03, às 14.21.29.png](images/Captura_de_ecra_2026-09-03_as_14.21.29.png)
    

![Captura de ecrã 2026-09-03, às 14.30.40.png](images/Captura_de_ecra_2026-09-03_as_14.30.40.png)

### When (When did this occur and is it still happening?)

![Captura de ecrã 2026-09-02, às 22.19.26.png](images/Captura_de_ecra_2026-09-02_as_22.19.26.png)

- **Status:** Contained and resolved. Offensive traffic was dropped by Active Response, verified by ICMP ping timeouts.

![Captura de ecrã 2026-09-02, às 22.18.33.png](images/Captura_de_ecra_2026-09-02_as_22.18.33.png)

![Captura de ecrã 2026-09-02, às 22.18.51.png](images/Captura_de_ecra_2026-09-02_as_22.18.51.png)

### Where (Where in the environment did this happen?)

- **Windows Endpoint:** Virtual Machine (`192.168.158.131`).
- **Linux Endpoint:** Ubuntu Server Virtual Machine (`192.168.158.130`).
- **Central Monitoring:** Wazuh SIEM Manager.

### Why (Why did this happen?)

- Controlled adversary emulation exercise designed to evaluate SIEM visibility, validate custom ruleset efficacy, and verify automated threat containment via Active Response.

### How (How did this happen?)

- Leveraged native OS tools (*Living off the Land* binaries such as `cmd.exe`, `powershell.exe`, `net.exe`, native `ssh` client) and standard Linux shell utilities.

## Recommendations

- **Automate Host-Based Containment:** Keep Wazuh Active Response (`firewall-drop`) enabled to drop brute-force sources dynamically via `iptables`.
- **Enforce Local Account Hardening:** Disable the `Guest` account centrally via Group Policy (GP is a windows feature that lets administrators centrally manage and configure user settings in Active directory or locally. In this case, it forces the Guest account to stay permanently disabled, even when someone activates the guest account) and configure high-severity alerts (Level 10+) for local group membership modifications (Windows Event IDs 4720, 4728, 4732).
- **Harden SSH Service:**
    - Disable password authentication in `/etc/ssh/sshd_config` (`PasswordAuthentication no`) in favor of public key authentication.
    - Restrict SSH access using firewall rules or management access control lists (ACLs). For example block port 22 to all the network.
- **Maintain File Integrity Monitoring (FIM):** Monitor critical directories (`/etc/`, `/tmp/`, system binary paths) for unauthorized modifications or staging behaviors.