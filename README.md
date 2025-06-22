# Auto AD Recon - NetExec Wrapper for Automated Active Directory Enumeration

Auto AD Recon is an advanced wrapper script for NetExec (https://github.com/Pennyw0rth/NetExec), designed to automate comprehensive Active Directory enumeration using both LDAP and SMB protocols. It simplifies and accelerates recon by combining NetExec’s built-in capabilities with powerful custom modules. The tool supports various authentication methods, detects misconfigured ADCS (ESC1–ESC8), analyzes abusable ACLs, supports BloodHound data collection, and organizes output with summaries and command tracking.

Features:
- Automated LDAP and SMB enumeration with built-in and custom NetExec modules
- Supports user/password, NTLM hash, and null session authentication
- Discovers and highlights Active Directory Certificate Services (ADCS) misconfigurations (ESC1–ESC8)
- Detects abusable access control entries (e.g., GenericAll, WriteDACL)
- Gathers session info, DNS zones, group memberships, LAPS, machine account quotas, trust relationships, and more
- Optional BloodHound-compatible data collection via --dns-server
- Custom delay control between each command
- Saves results in organized output with command breakdowns and status indicators

Installation:
Install NetExec (required):
pipx install netexec
# or
pip install netexec

Clone and set up this tool:
git clone https://github.com/azunhsephiroth77/auto-ad-recon-netexec.git
cd auto-ad-recon-netexec
chmod +x auto_ad_recon.py

Usage Examples:
# Full enumeration with credentials
python3 auto_ad_recon.py -t dc.domain.com -u username -pw password

# Null session enumeration
python3 auto_ad_recon.py -t 192.168.1.10 --null-session

# Hash-based authentication
python3 auto_ad_recon.py -t target.htb -u admin -H <NTLM_HASH>

# LDAP enumeration only
python3 auto_ad_recon.py -t dc.corp.local -u user -pw pass -p ldap

# SMB enumeration only
python3 auto_ad_recon.py -t 10.10.10.100 -u guest -pw '' -p smb

# Run built-in NetExec flags only
python3 auto_ad_recon.py -t target.htb -u user -pw pass --builtin-only

# Run custom modules only
python3 auto_ad_recon.py -t target.htb -u user -pw pass --modules-only

# Save output to a file
python3 auto_ad_recon.py -t target.htb -u user -pw pass -o output.txt

# Add delay between commands
python3 auto_ad_recon.py -t target.htb -u user -pw pass -d 5

# BloodHound-compatible collection
python3 auto_ad_recon.py -t dc.htb.local -u user -pw pass --dns-server 10.129.169.157

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

Included Custom Modules:

LDAP Modules:
  - user-desc, whoami, groupmembership, maq (machine quota)
  - laps (local admin passwords)
  - pso (password settings objects)
  - get-desc-users, get-userPassword, get-unixUserPassword
  - get-network, enum_trusts, pre2k, daclread, adcs

SMB Modules:
  - whoami, spider_plus (directory scan), enum_av
  - enum_dns, reg-query, handlekatz, enum_ca, timeroast

Author:
Abhishek Joshi  
GitHub: https://github.com/azunhsephiroth77  
LinkedIn: https://www.linkedin.com/in/reverse-shell  

Legal Notice:
This tool is intended for use in authorized security assessments, penetration testing, and educational labs only.
