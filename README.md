# Auto AD Recon - NetExec Wrapper for Automated Active Directory Enumeration

Auto AD Recon is a modular Python wrapper for NetExec (https://github.com/Pennyw0rth/NetExec) that performs extensive Active Directory enumeration over SMB and LDAP. It supports multiple authentication mechanisms and integrates custom modules for ACL analysis, ADCS misconfiguration detection (ESC1 to ESC8), machine quota discovery, LAPS retrieval, and BloodHound-compatible output. It is designed to accelerate recon during red team ops, internal pentests, and AD-focused CTFs.

Features:
- Multi-protocol AD enumeration using NetExec
- Supports authentication via password, NTLM hash, or null session
- Executes both built-in and custom NetExec modules in parallel
- Detects common ADCS misconfigs (ESC1 to ESC8)
- Parses ACLs for privilege escalation (e.g., GenericAll, WriteDACL)
- Extracts LAPS credentials, group memberships, trust relationships, and more
- Supports optional BloodHound collection using --dns-server
- Color-coded CLI output and optional result file writing
- Command-level summaries and error handling

Installation:
Install NetExec:
pipx install netexec
# or
pip install netexec

Clone the wrapper:
git clone https://github.com/azunhsephiroth77/auto-ad-recon-netexec.git
cd auto-ad-recon-netexec
chmod +x auto_ad_recon.py

Usage Examples:
# Full enumeration with credentials
python3 auto_ad_recon.py -t dc.domain.com -u username -pw password

# Null session enumeration
python3 auto_ad_recon.py -t 192.168.1.10 --null-session

# NTLM hash-based authentication
python3 auto_ad_recon.py -t target.htb -u admin -H <NTLM_HASH>

# LDAP-only enumeration
python3 auto_ad_recon.py -t dc.corp.local -u user -pw pass -p ldap

# SMB-only enumeration
python3 auto_ad_recon.py -t 10.10.10.100 -u guest -pw '' -p smb

# BloodHound-compatible data collection
python3 auto_ad_recon.py -t dc.htb.local -u user -pw pass --dns-server 10.129.169.157

# Run only built-in NetExec flags
python3 auto_ad_recon.py -t target.htb -u user -pw pass --builtin-only

# Run only custom modules
python3 auto_ad_recon.py -t target.htb -u user -pw pass --modules-only

# Save output to file
python3 auto_ad_recon.py -t target.htb -u user -pw pass -o output.txt

# Add delay between modules
python3 auto_ad_recon.py -t target.htb -u user -pw pass -d 5

Command Line Arguments:
  -t, --target           Target IP address or hostname (required)
  -u, --username         Username for authentication
  -pw, --password        Password for authentication
  -H                     NTLM hash for authentication
  --null-session         Use anonymous session
  -p, --protocols        Protocols to enumerate: ldap, smb, or both (default: both)
  --builtin-only         Run only NetExec built-in flags
  --modules-only         Run only custom modules
  --dns-server           DNS server IP (used for BloodHound collection)
  -d, --delay            Delay between commands in seconds (default: 2)
  -o, --output           Save all output to specified file

Included Modules:

LDAP Built-in Flags:
  --users, --groups, --asreproast, --kerberoasting, --get-sid, --bloodhound

LDAP Custom Modules:
  user-desc, whoami, groupmembership, maq, laps, pso,
  get-desc-users, get-userPassword, get-unixUserPassword,
  get-network, enum_trusts, pre2k, daclread, adcs

SMB Built-in Flags:
  --shares, --sessions, --loggedon-users, --local-groups, --pass-pol, --rid-brute

SMB Custom Modules:
  whoami, spider_plus, enum_av, enum_dns, handlekatz, reg-query, enum_ca, timeroast

Sample Output:
====================================================================================================
                    Auto AD Recon NetExec Script
                 Comprehensive AD Enumeration & Reconnaissance
====================================================================================================
[INFO] Target: dc.corp.local
[INFO] Protocols: ldap, smb
[INFO] Authentication: Credentials
****************************************************************************************************
PROCESSING PROTOCOL: LDAP
****************************************************************************************************
[1/7] Running: --users
Command: netexec ldap dc.corp.local -u admin -p password --users
--------------------------------------------------------------------------------
LDAP         10.10.10.100  389    DC01    [+] corp.local\admin:password
LDAP         10.10.10.100  389    DC01    [*] Enumerated 15 domain users
LDAP         10.10.10.100  389    DC01    john.doe                      2024-01-10
[SUCCESS] Flag --users completed successfully

Use Cases:
- Penetration testing of internal AD environments
- Red team enumeration and attack path discovery
- Blue team validation of exposure to common recon vectors
- CTF and HackTheBox-style AD recon automation
- Security research and lab automation

Legal Disclaimer:
This tool is intended for use in environments you own or are explicitly authorized to test. Unauthorized access to systems is illegal. Use responsibly and in accordance with applicable laws and ethical guidelines.

Author:
Abhishek Joshi  
GitHub: https://github.com/kernel-injection  
LinkedIn: https://www.linkedin.com/in/reverse-shell  
