#!/usr/bin/env python3
"""
Auto AD Recon NetExec Script
Automated Active Directory reconnaissance and enumeration tool using NetExec.
Supports comprehensive LDAP and SMB enumeration with various authentication methods.

Author: Abhishek Joshi (azunhsephiroth77)
GitHub: https://github.com/azunhsephiroth77
LinkedIn: https://www.linkedin.com/in/reverse-shell

Use only for authorized penetration testing and security research.
"""

import subprocess
import sys
import argparse
import time
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
    print(f"{Colors.BLUE}Author: {Colors.OKGREEN}Abhishek Joshi (azunhsephiroth77){Colors.ENDC}")
    print(f"{Colors.BLUE}GitHub: {Colors.OKCYAN}https://github.com/azunhsephiroth77{Colors.ENDC}")
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

# Enumeration modules for different protocols
AD_ENUMERATION_MODULES = {
    'ldap': [
        'user-desc',           # User Description Enumeration
        'whoami',              # Current User Information
        'groupmembership',     # User Group Membership
        'group-mem',           # Group Members Enumeration
        'maq',                 # Machine Account Quota
        'get-desc-users',      # User Descriptions
        'laps',                # LAPS Password Retrieval
        'get-network',         # Network Information
        'daclread',            # DACL Permissions
        'get-userPassword',    # User Passwords
        'get-unixUserPassword', # Unix User Passwords
        'pso',                 # Password Settings Objects
        'enum_trusts',         # Domain Trust Enumeration
        'pre2k',               # Pre-Windows 2000 Computers
        'adcs',                # Certificate Services
        'timeroast'            # Timeroasting Attack
    ],
    'smb': [
        'enum_av',             # Antivirus Enumeration
        'spider_plus',         # Advanced File Spidering
        'enum_dns',            # DNS Enumeration
        'enum_ca',             # Certificate Authority
        'handlekatz',          # Handle enumeration
        'reg-query',           # Registry Query
        'whoami',              # Current User (SMB)
        'timeroast'            # Timeroasting Attack
    ]
}

# Built-in NetExec flags organized by protocol
LDAP_BUILTIN_FLAGS = [
    '--users',                          # User Enumeration
    '--active-users',                   # Active Users Only
    '--groups',                         # Group Enumeration
    '--asreproast asrep_hashes.txt',    # ASREPRoasting Attack (with output file)
    '--kerberoasting kerb_hashes.txt',  # Kerberoasting Attack (with output file)
    '--bloodhound',                     # BloodHound Data Collection
    '--get-sid'                         # Domain SID Retrieval
]

SMB_BUILTIN_FLAGS = [
    '--shares',            # Share Enumeration
    '--sessions',          # Session Enumeration
    '--disks',             # Disk Enumeration
    '--loggedon-users',    # Logged-on Users
    '--local-groups',      # Local Groups
    '--pass-pol',          # Password Policy
    '--rid-brute',         # RID Bruteforcing
    '--users',             # Users via SMB
    '--groups'             # Groups via SMB
]

def run_builtin_enumeration(protocol: str, target_ip: str, username: str = None, password: str = None, null_session: bool = False) -> List[Dict]:
    """Run built-in NetExec enumeration flags."""
    results = []
    
    print(f"\n{Colors.GRAY}{'='*90}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}Running Built-in Enumeration for {protocol.upper()}{Colors.ENDC}")
    print(f"{Colors.GRAY}{'='*90}{Colors.ENDC}")
    
    # Select appropriate flags based on protocol
    if protocol == 'ldap':
        flags_to_run = LDAP_BUILTIN_FLAGS.copy()
    elif protocol == 'smb':
        flags_to_run = SMB_BUILTIN_FLAGS.copy()
    else:
        print_error(f"Unknown protocol: {protocol}")
        return []
    
    print_status(f"Running {len(flags_to_run)} built-in flags for {protocol.upper()}")
    
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
        
        # Add the flag (handle multi-word flags)
        flag_parts = flag.split()
        cmd.extend(flag_parts)
        
        print_command(' '.join(cmd))
        print(f"{Colors.GRAY}{'-' * 80}{Colors.ENDC}")
        
        try:
            # Just run the command and let output go directly to terminal
            result = subprocess.run(cmd, timeout=120)
            
            result_dict = {
                'type': 'builtin_flag',
                'flag': flag,
                'protocol': protocol,
                'returncode': result.returncode,
                'stdout': 'Output displayed above',
                'stderr': 'Errors displayed above'
            }
            
            results.append(result_dict)
            
            if result.returncode == 0:
                print_success(f"Flag {flag_parts[0]} completed successfully")
            else:
                print_error(f"Flag {flag_parts[0]} failed (return code: {result.returncode})")
        
        except subprocess.TimeoutExpired:
            print_warning(f"Flag {flag} timed out")
            results.append({
                'type': 'builtin_flag',
                'flag': flag,
                'protocol': protocol,
                'returncode': -1,
                'stdout': '',
                'stderr': 'Command timed out'
            })
        except Exception as e:
            print_error(f"Error running {flag}: {e}")
            results.append({
                'type': 'builtin_flag',
                'flag': flag,
                'protocol': protocol,
                'returncode': -1,
                'stdout': '',
                'stderr': str(e)
            })
        
        time.sleep(1)  # Small delay between commands
    
    return results

def run_module(protocol: str, target_ip: str, module: str, username: str = None, password: str = None, null_session: bool = False, module_options: str = None) -> Dict:
    """Run a specific module against the target."""
    cmd = ['netexec', protocol, target_ip]
    
    # Add authentication BEFORE module
    if null_session:
        cmd.extend(['-u', '', '-p', ''])
    elif username:
        cmd.extend(['-u', username])
        if password:
            cmd.extend(['-p', password])
    
    # Add module AFTER authentication
    cmd.extend(['-M', module])
    
    # Add module options if provided
    if module_options:
        cmd.extend(['-o', module_options])
    
    print_module_header(module, protocol, target_ip)
    if module_options:
        print(f"{Colors.YELLOW}Options: {Colors.OKGREEN}{module_options}{Colors.ENDC}")
    print_command(' '.join(cmd))
    print(f"{Colors.ORANGE}{'='*70}{Colors.ENDC}")
    
    try:
        # Just run the command and let output go directly to terminal
        result = subprocess.run(cmd, timeout=180)
        
        # Print completion status
        if result.returncode == 0:
            print_success(f"Module {module} completed successfully")
        else:
            print_error(f"Module {module} failed (return code: {result.returncode})")
        
        return {
            'type': 'module',
            'module': module,
            'protocol': protocol,
            'options': module_options,
            'returncode': result.returncode,
            'stdout': 'Output displayed above',
            'stderr': 'Errors displayed above'
        }
    
    except subprocess.TimeoutExpired:
        return {
            'type': 'module',
            'module': module,
            'protocol': protocol,
            'options': module_options,
            'returncode': -1,
            'stdout': '',
            'stderr': 'Module execution timed out'
        }
    except Exception as e:
        return {
            'type': 'module',
            'module': module,
            'protocol': protocol,
            'options': module_options,
            'returncode': -1,
            'stdout': '',
            'stderr': str(e)
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
  
  # LDAP only with output file
  python3 auto_ad_recon.py -t dc.domain.local -u admin -pw pass -p ldap -o results.txt
  
  # SMB enumeration only
  python3 auto_ad_recon.py -t 10.10.10.100 -u guest -pw '' -p smb
  
  # Run custom modules only (skip built-in flags)
  python3 auto_ad_recon.py -t target.htb --null-session --modules-only
  
  # Run built-in flags only (skip custom modules)
  python3 auto_ad_recon.py -t target.htb -u user -pw pass --builtin-only

Author: Abhishek Joshi (azunhsephiroth77)
GitHub: https://github.com/azunhsephiroth77
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
    parser.add_argument('--dns-server', help='DNS server for BloodHound collection')
    
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
                null_session=args.null_session
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
                    module_options = 'USER="administrator"'
                elif module == 'group-mem':
                    module_options = 'GROUP="Domain Users"'
                elif module == 'daclread':
                    module_options = 'TARGET=Administrator ACTION=read'
                
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
                
                # No need to print results again since they're printed in run_module
                # Delay between modules
                if i < len(modules):
                    time.sleep(args.delay)
    
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
                f.write(f"Total commands: {len(all_results)}\n")
                f.write(f"Successful: {successful}\n")
                f.write(f"Failed: {failed}\n")
                f.write(f"Author: Abhishek Joshi (azunhsephiroth77)\n")
                f.write(f"GitHub: https://github.com/azunhsephiroth77\n\n")
                
                for result in all_results:
                    f.write(f"\n{'='*80}\n")
                    if result['type'] == 'builtin_flag':
                        f.write(f"Built-in Flag: {result['flag']} ({result['protocol'].upper()})\n")
                    else:
                        f.write(f"Module: {result['module']} ({result['protocol'].upper()})\n")
                        if result.get('options'):
                            f.write(f"Options: {result['options']}\n")
                    f.write(f"Return Code: {result['returncode']}\n")
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
                "• ADCS misconfigurations and certificate templates",
                "• Network subnet information",
                "• Password policies (PSO)",
                "• Service accounts (Kerberoasting targets)",
                "• ASREPRoastable accounts",
                "• SMB shares and permissions",
                "• Active sessions and logged-on users"
            ]
            for finding in findings:
                print(f"{Colors.OKGREEN}{finding}{Colors.ENDC}")
            
        except Exception as e:
            print_error(f"Error saving results: {e}")

    print(f"\n{Colors.GRAY}{'='*120}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}Auto AD Recon completed successfully!{Colors.ENDC}")
    print(f"{Colors.BLUE}Author: {Colors.OKGREEN}Abhishek Joshi (azunhsephiroth77){Colors.ENDC}")
    print(f"{Colors.BLUE}GitHub: {Colors.OKCYAN}https://github.com/azunhsephiroth77{Colors.ENDC}")
    print(f"{Colors.GRAY}{'='*120}{Colors.ENDC}")

if __name__ == "__main__":
    main()
