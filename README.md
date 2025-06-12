# Auto AD Recon NetExec Script

🔍 **Comprehensive Active Directory Enumeration & Reconnaissance Tool**

An automated Python script that leverages NetExec to perform thorough Active Directory reconnaissance across multiple protocols. Features a professional color-coded interface and supports various authentication methods for complete AD enumeration.

## 🚀 Features

### Core Functionality
- **Multi-Protocol Support**: Automated LDAP and SMB enumeration
- **Comprehensive Coverage**: 40+ enumeration techniques including built-in flags and custom modules
- **Professional Interface**: Color-coded output with clear visual hierarchy
- **Real-time Results**: Live command output display with immediate feedback
- **Flexible Authentication**: Supports credentials, null sessions, and hash-based authentication

### Enumeration Capabilities

#### LDAP Enumeration (23 techniques)
**Built-in Flags:**
- User enumeration (`--users`, `--active-users`)
- Group enumeration (`--groups`)
- ASREPRoasting (`--asreproast`)
- Kerberoasting (`--kerberoasting`)
- BloodHound data collection (`--bloodhound`)
- Domain SID retrieval (`--get-sid`)

**Custom Modules:**
- `user-desc` - User description enumeration
- `whoami` - Current user identification
- `groupmembership` - User group membership analysis
- `group-mem` - Group member enumeration
- `maq` - Machine account quota check
- `laps` - LAPS password retrieval
- `get-network` - Network information gathering
- `daclread` - DACL permissions analysis
- `adcs` - Certificate services enumeration
- `timeroast` - Timeroasting attacks
- And more...

#### SMB Enumeration (17 techniques)
**Built-in Flags:**
- Share enumeration (`--shares`)
- Session enumeration (`--sessions`)
- Logged-on users (`--loggedon-users`)
- Local groups (`--local-groups`)
- Password policy (`--pass-pol`)
- RID bruteforcing (`--rid-brute`)

**Custom Modules:**
- `enum_av` - Antivirus enumeration
- `spider_plus` - Advanced file spidering
- `handlekatz` - Handle enumeration
- `reg-query` - Registry queries
- And more...

## 📋 Prerequisites

- **NetExec** installed and accessible in PATH
- **Python 3.6+**
- Target Active Directory environment
- Appropriate authorization for testing

### Installing NetExec
```bash
# Install via pipx (recommended)
pipx install netexec

# Or via pip
pip install netexec

🔧 Installation
# Clone the repository
git clone https://github.com/azunhsephiroth77/auto-ad-recon-netexec.git
cd auto-ad-recon-netexec

# Make executable (Linux/Mac)
chmod +x auto_ad_recon.py

💻 Usage
Basic Usage

# Full enumeration with credentials
python3 auto_ad_recon.py -t dc.domain.com -u username -pw password

# Null session enumeration
python3 auto_ad_recon.py -t 192.168.1.10 --null-session

# Hash-based authentication
python3 auto_ad_recon.py -t target.htb -u admin -H <NTLM_HASH>

Advanced Options

# LDAP enumeration only
python3 auto_ad_recon.py -t dc.corp.local -u user -pw pass -p ldap

# SMB enumeration only
python3 auto_ad_recon.py -t 10.10.10.100 -u guest -pw '' -p smb

# Built-in flags only (faster execution)
python3 auto_ad_recon.py -t target.htb -u user -pw pass --builtin-only

# Custom modules only
python3 auto_ad_recon.py -t target.htb -u user -pw pass --modules-only

# Save results to file
python3 auto_ad_recon.py -t target.htb -u user -pw pass -o results.txt

# Custom delay between commands
python3 auto_ad_recon.py -t target.htb -u user -pw pass -d 5

Command Line Options

Required:
  -t, --target          Target IP address or hostname

Authentication:
  -u, --username        Username for authentication
  -pw, --password       Password for authentication
  --null-session        Use null session (anonymous)

Protocol Options:
  -p, --protocols       Protocols to test: ldap, smb, or both (default: both)

Execution Control:
  --builtin-only        Run only built-in flags
  --modules-only        Run only custom modules
  -d, --delay          Delay between commands (default: 2s)

Output:
  -o, --output         Save results to file

📊 Sample Output

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
LDAP         10.10.10.100  389    DC01    [*] Windows Server 2019 Build 17763
LDAP         10.10.10.100  389    DC01    [+] corp.local\admin:password
LDAP         10.10.10.100  389    DC01    [*] Enumerated 15 domain users
LDAP         10.10.10.100  389    DC01    Administrator                 2024-01-15
LDAP         10.10.10.100  389    DC01    Guest                         <never>
LDAP         10.10.10.100  389    DC01    john.doe                      2024-01-10
[SUCCESS] Flag --users completed successfully

🎯 Use Cases

Penetration Testing: Comprehensive AD reconnaissance during authorized engagements
Red Team Operations: Initial enumeration and attack surface mapping
Security Assessments: Identifying misconfigurations and security gaps
CTF/HackTheBox: Automated enumeration for AD-focused challenges
Security Research: Educational tool for understanding AD enumeration techniques

⚠️ Legal Disclaimer
This tool is designed for authorized security testing only. Users must ensure they have explicit permission to test target systems. Unauthorized access to computer systems is illegal and unethical.

✅ Use only on systems you own or have explicit written permission to test
✅ Follow responsible disclosure practices
✅ Comply with all applicable laws and regulations
❌ Do not use for malicious purposes

🤝 Contributing
Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.
Areas for Contribution

Additional NetExec modules
Enhanced output formatting
New authentication methods
Performance optimizations
Documentation improvements

📝 License
This project is licensed under the MIT License - see the LICENSE file for details.
🔗 References

NetExec Documentation
Active Directory Security Testing Guide
MITRE ATT&CK Framework

👨‍💻 Author
Abhishek Joshi (azunhsephiroth77)

GitHub: @azunhsephiroth77
LinkedIn: reverse-shell


⭐ Star this repository if you find it useful!
Built with ❤️ for the cybersecurity community