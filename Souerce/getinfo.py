#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_no_winutils_enhanced.py

Enhanced system information collector without Windows CLI utilities.
Uses only Python stdlib + ctypes + winreg.
Fully configurable via config file with enable/disable for each log type.
"""

import os
import sys
import re
import ctypes
import ctypes.wintypes as wt
import socket
import platform
import locale
from datetime import datetime
from pathlib import Path
import winreg
import traceback
import subprocess
import json
from typing import Dict, List, Any, Optional

# ----------------- Default Configuration -----------------
DEFAULT_CONFIG = {
    "output_directory": None,  # None = auto-create in current directory
    "max_user_names": 500,
    "do_reg_export": False,    # Requires admin rights
    
    # Enable/disable specific logs
    "logs": {
        "system_info": True,
        "os_edition": True,
        "users_list": True,
        "user_detailed": True,
        "user_groups_sid_rid": True,
        "pc_characteristics": True,
        "installed_programs": True,
        "processes_detailed": True,
        "network_adapters": True,
        "services_info": True,
        "hotfixes_list": True,
        "environment_vars": True,
        "registry_export": False,  # Requires admin
        "system_uptime": True,
        "locale_info": True,
        "memory_detailed": True,
        "disk_detailed": True,
    }
}

# ----------------- Configuration Manager -----------------
class ConfigManager:
    def __init__(self, config_path: str = "collector_config.txt"):
        self.config_path = config_path
        self.config = DEFAULT_CONFIG.copy()
        
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    file_content = f.read().strip()
                    
                if file_content.startswith('{'):
                    # JSON format
                    loaded_config = json.loads(file_content)
                else:
                    # Simple key=value format (backward compatibility)
                    loaded_config = self._parse_simple_config(file_content)
                
                # Deep merge with default config
                self._deep_merge(self.config, loaded_config)
                print(f"[+] Configuration loaded from {self.config_path}")
                
            except Exception as e:
                print(f"[!] Error loading config: {e}, using defaults")
        else:
            self.create_default_config()
            
        return self.config
    
    def _parse_simple_config(self, content: str) -> Dict[str, Any]:
        """Parse simple key=value config format"""
        config = {}
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Handle boolean values
                if value.upper() in ['TRUE', 'YES', 'ON', '1']:
                    value = True
                elif value.upper() in ['FALSE', 'NO', 'OFF', '0']:
                    value = False
                elif value.isdigit():
                    value = int(value)
                elif value.replace('.', '').isdigit():
                    value = float(value)
                    
                # Handle nested logs configuration
                if key.startswith('logs.'):
                    log_key = key[5:]  # Remove 'logs.' prefix
                    if 'logs' not in config:
                        config['logs'] = {}
                    config['logs'][log_key] = value
                else:
                    config[key] = value
                    
        return config
    
    def _deep_merge(self, target: Dict, source: Dict):
        """Recursively merge source dict into target dict"""
        for key, value in source.items():
            if (key in target and isinstance(target[key], dict) 
                and isinstance(value, dict)):
                self._deep_merge(target[key], value)
            else:
                target[key] = value
    
    def create_default_config(self):
        """Create default configuration file"""
        try:
            # Create both JSON and simple format for user choice
            with open(self.config_path, 'w', encoding='utf-8') as f:
                f.write("# System Collector Configuration\n")
                f.write("# Format: key=value or JSON (below)\n\n")
                
                # Simple format
                f.write("# Simple configuration (uncomment and modify):\n")
                for key, value in DEFAULT_CONFIG.items():
                    if key != 'logs':
                        if value is None:
                            f.write(f"#{key}=\n")
                        else:
                            f.write(f"#{key}={value}\n")
                
                f.write("\n# Logs configuration:\n")
                for log_key, log_value in DEFAULT_CONFIG['logs'].items():
                    f.write(f"#logs.{log_key}={log_value}\n")
                
                f.write("\n\n# JSON configuration (alternative):\n")
                f.write("#" + json.dumps(DEFAULT_CONFIG, indent=4, ensure_ascii=False))
                
            print(f"[+] Default configuration created: {self.config_path}")
            print("[!] Please edit the config file and restart the script")
            
        except Exception as e:
            print(f"[!] Failed to create config: {e}")

# ----------------- Enhanced Utilities -----------------
def now_ts():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def safe_filename(name: str, maxlen: int = 200) -> str:
    if not name:
        return "noname"
    name = str(name)
    name = re.sub(r'[\\/:"*?<>|]+', '_', name)
    name = re.sub(r'[\x00-\x1f]+', '_', name).strip()
    name = name.strip()
    if len(name) > maxlen:
        name = name[:maxlen]
    if not name:
        return "file"
    return name

def write_utf8_bom(path: str, text: str):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8', errors='replace', newline='\n') as f:
            f.write('\ufeff')
            f.write(text)
    except Exception as e:
        print(f"[!] Failed to write {path}: {e}")

def append_error(logpath: str, message: str):
    try:
        with open(logpath, 'a', encoding='utf-8', errors='replace') as f:
            f.write(f"{datetime.now().isoformat()} - {message}\n")
    except Exception:
        pass

# ----------------- Output Manager -----------------
class OutputManager:
    def __init__(self, base_outdir: str):
        self.base_outdir = base_outdir
        self.files_created = []
        
    def write_log(self, filename: str, content: str, logpath: str) -> bool:
        """Write log file and track it"""
        try:
            full_path = os.path.join(self.base_outdir, filename)
            write_utf8_bom(full_path, content)
            self.files_created.append(filename)
            return True
        except Exception as e:
            append_error(logpath, f"write_log {filename}: {e}")
            return False

# ----------------- Enhanced System Information -----------------
def collect_system_info(out_mgr: OutputManager, logpath: str, config: Dict) -> bool:
    if not config['logs']['system_info']:
        return True
        
    try:
        info = []
        info.append("=== SYSTEM INFORMATION ===")
        info.append(f"Hostname: {socket.gethostname()}")
        info.append(f"Platform: {platform.platform()}")
        info.append(f"System: {platform.system()} {platform.release()} {platform.version()}")
        info.append(f"Machine: {platform.machine()}")
        info.append(f"Processor: {platform.processor()}")
        info.append(f"Python: {platform.python_version()}")
        
        # Architecture detection
        try:
            is_64bit = platform.machine().endswith('64')
            info.append(f"Architecture: {'64-bit' if is_64bit else '32-bit'}")
        except:
            pass
            
        return out_mgr.write_log("system_info.txt", "\n".join(info), logpath)
    except Exception as e:
        append_error(logpath, f"collect_system_info: {e}")
        return False

def collect_os_edition(out_mgr: OutputManager, logpath: str, config: Dict) -> bool:
    if not config['logs']['os_edition']:
        return True
        
    try:
        info = ["=== OS EDITION & LICENSE ==="]
        
        # Get OS edition from registry
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                              r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                try:
                    product_name = winreg.QueryValueEx(key, "ProductName")[0]
                    info.append(f"Product Name: {product_name}")
                except:
                    pass
                    
                try:
                    edition_id = winreg.QueryValueEx(key, "EditionID")[0]
                    info.append(f"Edition ID: {edition_id}")
                except:
                    pass
                    
                try:
                    build_number = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
                    info.append(f"Build Number: {build_number}")
                except:
                    pass
                    
                try:
                    install_date = winreg.QueryValueEx(key, "InstallDate")[0]
                    if install_date:
                        dt = datetime.fromtimestamp(install_date)
                        info.append(f"Install Date: {dt}")
                except:
                    pass
        except Exception as e:
            info.append(f"Registry access failed: {e}")
            
        return out_mgr.write_log("os_edition.txt", "\n".join(info), logpath)
    except Exception as e:
        append_error(logpath, f"collect_os_edition: {e}")
        return False

# ----------------- Enhanced User Information -----------------
def collect_users_with_groups(out_mgr: OutputManager, logpath: str, config: Dict) -> List[str]:
    users = []
    
    if config['logs']['users_list']:
        try:
            users_dir = Path("C:/Users")
            if users_dir.exists() and users_dir.is_dir():
                for p in users_dir.iterdir():
                    try:
                        if p.is_dir() and not p.name.startswith('.'):
                            users.append(p.name)
                    except Exception:
                        continue
        except Exception as e:
            append_error(logpath, f"collect_users (C:\\Users): {e}")

    # Get users from registry ProfileList
    if config['logs']['user_groups_sid_rid']:
        try:
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as pk:
                i = 0
                while True:
                    try:
                        sid = winreg.EnumKey(pk, i)
                        i += 1
                        try:
                            with winreg.OpenKey(pk, sid) as sp:
                                try:
                                    prof = winreg.QueryValueEx(sp, "ProfileImagePath")[0]
                                    if prof:
                                        base = os.path.basename(str(prof))
                                        if base and base not in users:
                                            users.append(base)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                    except OSError:
                        break
        except Exception as e:
            append_error(logpath, f"collect_users (registry): {e}")

    users = list(dict.fromkeys(users))[:config['max_user_names']]
    
    if config['logs']['users_list']:
        out_mgr.write_log("users_list.txt", "\n".join(users), logpath)
    
    return users

def collect_user_groups_sid_rid(out_mgr: OutputManager, logpath: str, config: Dict):
    if not config['logs']['user_groups_sid_rid']:
        return
        
    try:
        groups_info = ["=== USER GROUPS, SIDs, and RIDs ==="]
        
        # This is a simplified version - in real implementation you'd use
        # ctypes to call LSA functions to get SIDs and RIDs properly
        try:
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as pk:
                i = 0
                while True:
                    try:
                        sid = winreg.EnumKey(pk, i)
                        i += 1
                        groups_info.append(f"\nSID: {sid}")
                        
                        try:
                            with winreg.OpenKey(pk, sid) as sp:
                                try:
                                    prof = winreg.QueryValueEx(sp, "ProfileImagePath")[0]
                                    groups_info.append(f"  Profile Path: {prof}")
                                except Exception:
                                    pass
                                    
                                try:
                                    sid_ref = winreg.QueryValueEx(sp, "Sid")[0]
                                    groups_info.append(f"  SID Ref: {sid_ref}")
                                except Exception:
                                    pass
                        except Exception:
                            pass
                            
                    except OSError:
                        break
        except Exception as e:
            groups_info.append(f"Error reading ProfileList: {e}")
            
        out_mgr.write_log("user_groups_sid_rid.txt", "\n".join(groups_info), logpath)
        
    except Exception as e:
        append_error(logpath, f"collect_user_groups_sid_rid: {e}")

def collect_user_detailed_info(users: List[str], out_mgr: OutputManager, logpath: str, config: Dict):
    if not config['logs']['user_detailed']:
        return
        
    for username in users:
        try:
            user_safe = safe_filename(username)
            user_home = Path(f"C:/Users/{username}")
            
            if not user_home.exists():
                continue
                
            lines = [f"=== DETAILED INFO FOR USER: {username} ==="]
            lines.append(f"Home folder: {user_home}")
            
            # Basic stats
            total_files = 0
            total_dirs = 0
            total_size = 0
            recent_files = []
            
            try:
                for root, dirs, files in os.walk(user_home):
                    total_dirs += len(dirs)
                    total_files += len(files)
                    for f in files:
                        try:
                            fpath = Path(root) / f
                            stat = fpath.stat()
                            total_size += stat.st_size
                            recent_files.append((fpath, stat.st_mtime, stat.st_size))
                        except Exception:
                            continue
            except Exception as e:
                lines.append(f"Error walking directory: {e}")
            
            lines.append(f"Total files: {total_files}")
            lines.append(f"Total directories: {total_dirs}")
            lines.append(f"Total size: {total_size:,} bytes ({total_size/1024/1024:.2f} MB)")
            
            # Recent files
            if recent_files:
                recent_files.sort(key=lambda x: x[1], reverse=True)
                lines.append("\n10 most recently modified files:")
                for f, mtime, size in recent_files[:10]:
                    lines.append(f"  {f}")
                    lines.append(f"    Modified: {datetime.fromtimestamp(mtime)}")
                    lines.append(f"    Size: {size:,} bytes")
            
            out_mgr.write_log(f"user_{user_safe}_detailed.txt", "\n".join(lines), logpath)
            
        except Exception as e:
            append_error(logpath, f"collect_user_detailed_info for {username}: {e}")

# ----------------- Enhanced PC Characteristics -----------------
def collect_pc_characteristics(out_mgr: OutputManager, logpath: str, config: Dict) -> bool:
    if not config['logs']['pc_characteristics']:
        return True
        
    try:
        lines = ["=== PC CHARACTERISTICS ==="]
        lines.append(f"Hostname: {socket.gethostname()}")
        lines.append(f"Platform: {platform.platform()}")
        
        # CPU info
        try:
            lines.append(f"Processor: {platform.processor()}")
            lines.append(f"CPU Cores: {os.cpu_count()}")
        except:
            pass
            
        # RAM info
        if config['logs']['memory_detailed']:
            try:
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", wt.DWORD),
                        ("dwMemoryLoad", wt.DWORD),
                        ("ullTotalPhys", ctypes.c_uint64),
                        ("ullAvailPhys", ctypes.c_uint64),
                        ("ullTotalPageFile", ctypes.c_uint64),
                        ("ullAvailPageFile", ctypes.c_uint64),
                        ("ullTotalVirtual", ctypes.c_uint64),
                        ("ullAvailVirtual", ctypes.c_uint64),
                    ]
                
                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                
                lines.append("\n--- MEMORY INFORMATION ---")
                lines.append(f"Memory Load: {stat.dwMemoryLoad}%")
                lines.append(f"Total Physical: {stat.ullTotalPhys:,} bytes ({stat.ullTotalPhys/1024/1024/1024:.2f} GB)")
                lines.append(f"Available Physical: {stat.ullAvailPhys:,} bytes ({stat.ullAvailPhys/1024/1024/1024:.2f} GB)")
                lines.append(f"Total Page File: {stat.ullTotalPageFile:,} bytes")
                lines.append(f"Available Page File: {stat.ullAvailPageFile:,} bytes")
                lines.append(f"Total Virtual: {stat.ullTotalVirtual:,} bytes")
                lines.append(f"Available Virtual: {stat.ullAvailVirtual:,} bytes")
            except Exception as e:
                lines.append(f"Memory info error: {e}")
        
        # Disk information
        if config['logs']['disk_detailed']:
            try:
                lines.append("\n--- DISK INFORMATION ---")
                drives = []
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                    if bitmask & 1:
                        drives.append(letter)
                    bitmask >>= 1
                
                for drive in drives:
                    path = f"{drive}:\\"
                    try:
                        total = ctypes.c_ulonglong()
                        free = ctypes.c_ulonglong()
                        ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                            ctypes.c_wchar_p(path), None, 
                            ctypes.byref(total), ctypes.byref(free)
                        )
                        used = total.value - free.value
                        usage_pct = (used / total.value * 100) if total.value > 0 else 0
                        
                        lines.append(f"Drive {drive}:")
                        lines.append(f"  Total: {total.value:,} bytes ({total.value/1024/1024/1024:.2f} GB)")
                        lines.append(f"  Free: {free.value:,} bytes ({free.value/1024/1024/1024:.2f} GB)")
                        lines.append(f"  Used: {used:,} bytes ({used/1024/1024/1024:.2f} GB)")
                        lines.append(f"  Usage: {usage_pct:.1f}%")
                    except Exception:
                        lines.append(f"Drive {drive}: [access denied or error]")
            except Exception as e:
                lines.append(f"Disk info error: {e}")
        
        return out_mgr.write_log("pc_characteristics.txt", "\n".join(lines), logpath)
        
    except Exception as e:
        append_error(logpath, f"collect_pc_characteristics: {e}")
        return False

# ----------------- Enhanced Processes -----------------
def collect_processes_detailed(out_mgr: OutputManager, logpath: str, config: Dict) -> bool:
    if not config['logs']['processes_detailed']:
        return True
        
    try:
        TH32CS_SNAPPROCESS = 0x00000002
        
        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wt.DWORD),
                ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", wt.DWORD),
                ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wt.DWORD),
                ("szExeFile", wt.CHAR * 260)
            ]
        
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
        Process32First = kernel32.Process32First
        Process32Next = kernel32.Process32Next
        CloseHandle = kernel32.CloseHandle
        
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == wt.HANDLE(-1).value:
            append_error(logpath, "CreateToolhelp32Snapshot failed")
            return False
        
        pe = PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
        res = Process32First(snapshot, ctypes.byref(pe))
        
        processes = ["=== PROCESS LIST ==="]
        processes.append("PID\tPPID\tThreads\tName")
        processes.append("-" * 50)
        
        if not res:
            append_error(logpath, "Process32First failed")
        else:
            while res:
                try:
                    name = pe.szExeFile.decode('utf-8', errors='replace') 
                except Exception:
                    name = str(pe.szExeFile)
                
                processes.append(f"{pe.th32ProcessID}\t{pe.th32ParentProcessID}\t{pe.cntThreads}\t{name}")
                res = Process32Next(snapshot, ctypes.byref(pe))
        
        try:
            CloseHandle(snapshot)
        except Exception:
            pass
        
        return out_mgr.write_log("processes_detailed.txt", "\n".join(processes), logpath)
        
    except Exception as e:
        append_error(logpath, f"collect_processes_detailed: {e}")
        return False

# ----------------- Enhanced Network Information -----------------
def collect_network_adapters_detailed(out_mgr: OutputManager, logpath: str, config: Dict) -> bool:
    if not config['logs']['network_adapters']:
        return True
        
    try:
        iphlpapi = ctypes.WinDLL('iphlpapi', use_last_error=True)
        AF_UNSPEC = 0
        
        class IP_ADAPTER_ADDRESSES(ctypes.Structure):
            pass
            
        PIP_ADAPTER_ADDRESSES = ctypes.POINTER(IP_ADAPTER_ADDRESSES)
        IP_ADAPTER_ADDRESSES._fields_ = [
            ("Length", wt.ULONG),
            ("IfIndex", wt.DWORD),
            ("Next", PIP_ADAPTER_ADDRESSES),
            ("AdapterName", ctypes.c_char_p),
            ("FirstUnicastAddress", ctypes.c_void_p),
            ("FirstAnycastAddress", ctypes.c_void_p),
            ("FirstMulticastAddress", ctypes.c_void_p),
            ("FirstDnsServerAddress", ctypes.c_void_p),
            ("DnsSuffix", ctypes.c_wchar_p),
            ("Description", ctypes.c_wchar_p),
            ("FriendlyName", ctypes.c_wchar_p),
            ("PhysicalAddress", wt.BYTE * 8),
            ("PhysicalAddressLength", wt.DWORD),
            ("Flags", wt.DWORD),
            ("Mtu", wt.DWORD),
            ("IfType", wt.DWORD),
            ("OperStatus", wt.DWORD),
        ]
        
        GetAdaptersAddresses = iphlpapi.GetAdaptersAddresses
        GetAdaptersAddresses.argtypes = [wt.ULONG, wt.ULONG, ctypes.c_void_p, 
                                       PIP_ADAPTER_ADDRESSES, ctypes.POINTER(wt.ULONG)]
        GetAdaptersAddresses.restype = wt.ULONG
        
        size = wt.ULONG(15 * 1024)
        buf = ctypes.create_string_buffer(size.value)
        addr = ctypes.cast(buf, PIP_ADAPTER_ADDRESSES)
        rc = GetAdaptersAddresses(AF_UNSPEC, 0, None, addr, ctypes.byref(size))
        
        adapters = ["=== NETWORK ADAPTERS ==="]
        
        if rc == 0:
            cur = addr
            while cur:
                try:
                    friendly = cur.contents.FriendlyName or "N/A"
                    desc = cur.contents.Description or "N/A"
                    mac_len = cur.contents.PhysicalAddressLength
                    mac = ":".join(f"{cur.contents.PhysicalAddress[i]:02x}" 
                                 for i in range(mac_len)) if mac_len else "N/A"
                    dns_suffix = cur.contents.DnsSuffix or "N/A"
                    
                    adapters.append(f"Adapter: {friendly}")
                    adapters.append(f"  Description: {desc}")
                    adapters.append(f"  MAC: {mac}")
                    adapters.append(f"  DNS Suffix: {dns_suffix}")
                    adapters.append(f"  Type: {cur.contents.IfType}")
                    adapters.append(f"  Status: {cur.contents.OperStatus}")
                    adapters.append("")
                    
                except Exception:
                    pass
                cur = cur.contents.Next
        else:
            adapters.append("[Failed to retrieve adapter information]")
        
        return out_mgr.write_log("network_adapters.txt", "\n".join(adapters), logpath)
        
    except Exception as e:
        append_error(logpath, f"collect_network_adapters_detailed: {e}")
        return False

# ----------------- Additional Information Collectors -----------------
def collect_services_info(out_mgr: OutputManager, logpath: str, config: Dict) -> bool:
    if not config['logs']['services_info']:
        return True
        
    try:
        # Simplified service enumeration via registry
        services = ["=== SERVICES INFORMATION ==="]
        
        try:
            key_path = r"SYSTEM\CurrentControlSet\Services"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as services_key:
                i = 0
                while True:
                    try:
                        service_name = winreg.EnumKey(services_key, i)
                        i += 1
                        
                        try:
                            with winreg.OpenKey(services_key, service_name) as service:
                                services.append(f"\nService: {service_name}")
                                
                                try:
                                    display_name = winreg.QueryValueEx(service, "DisplayName")[0]
                                    services.append(f"  Display Name: {display_name}")
                                except:
                                    pass
                                    
                                try:
                                    description = winreg.QueryValueEx(service, "Description")[0]
                                    services.append(f"  Description: {description}")
                                except:
                                    pass
                                    
                                try:
                                    image_path = winreg.QueryValueEx(service, "ImagePath")[0]
                                    services.append(f"  Image Path: {image_path}")
                                except:
                                    pass
                                    
                        except Exception:
                            pass
                            
                    except OSError:
                        break
        except Exception as e:
            services.append(f"Error reading services: {e}")
        
        return out_mgr.write_log("services_info.txt", "\n".join(services), logpath)
        
    except Exception as e:
        append_error(logpath, f"collect_services_info: {e}")
        return False

def collect_hotfixes_list(out_mgr: OutputManager, logpath: str, config: Dict) -> bool:
    if not config['logs']['hotfixes_list']:
        return True
        
    try:
        hotfixes = ["=== INSTALLED UPDATES/HOTFIXES ==="]
        
        try:
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as packages_key:
                i = 0
                count = 0
                while count < 100:  # Limit output
                    try:
                        package_name = winreg.EnumKey(packages_key, i)
                        i += 1
                        
                        if any(hotfix_indicator in package_name for hotfix_indicator in 
                              ['KB', 'Hotfix', 'Update']):
                            hotfixes.append(package_name)
                            count += 1
                            
                    except OSError:
                        break
        except Exception:
            hotfixes.append("[Could not retrieve hotfix list from registry]")
        
        return out_mgr.write_log("hotfixes_list.txt", "\n".join(hotfixes), logpath)
        
    except Exception as e:
        append_error(logpath, f"collect_hotfixes_list: {e}")
        return False

def collect_environment_vars(out_mgr: OutputManager, logpath: str, config: Dict) -> bool:
    if not config['logs']['environment_vars']:
        return True
        
    try:
        env_vars = ["=== ENVIRONMENT VARIABLES ==="]
        
        for key, value in sorted(os.environ.items()):
            env_vars.append(f"{key}={value}")
        
        return out_mgr.write_log("environment_vars.txt", "\n".join(env_vars), logpath)
        
    except Exception as e:
        append_error(logpath, f"collect_environment_vars: {e}")
        return False

def collect_system_uptime(out_mgr: OutputManager, logpath: str, config: Dict) -> bool:
    if not config['logs']['system_uptime']:
        return True
        
    try:
        uptime_info = ["=== SYSTEM UPTIME ==="]
        
        try:
            tick_count = ctypes.windll.kernel32.GetTickCount64()
            if tick_count:
                days = tick_count // (1000 * 60 * 60 * 24)
                hours = (tick_count % (1000 * 60 * 60 * 24)) // (1000 * 60 * 60)
                minutes = (tick_count % (1000 * 60 * 60)) // (1000 * 60)
                
                uptime_info.append(f"Uptime: {days} days, {hours} hours, {minutes} minutes")
                uptime_info.append(f"Total milliseconds: {tick_count:,}")
            else:
                uptime_info.append("Could not retrieve uptime")
        except:
            uptime_info.append("Uptime retrieval failed")
        
        return out_mgr.write_log("system_uptime.txt", "\n".join(uptime_info), logpath)
        
    except Exception as e:
        append_error(logpath, f"collect_system_uptime: {e}")
        return False

def collect_locale_info(out_mgr: OutputManager, logpath: str, config: Dict) -> bool:
    if not config['logs']['locale_info']:
        return True
        
    try:
        locale_info = ["=== LOCALE & REGIONAL SETTINGS ==="]
        
        try:
            locale_info.append(f"Preferred encoding: {locale.getpreferredencoding(False)}")
        except:
            pass
            
        try:
            import time
            locale_info.append(f"Current time: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        except:
            pass
            
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Control Panel\\International") as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        i += 1
                        if any(keyword in name.lower() for keyword in 
                              ['locale', 'country', 'language', 'format']):
                            locale_info.append(f"{name}: {value}")
                    except OSError:
                        break
        except Exception as e:
            locale_info.append(f"Registry access failed: {e}")
        
        return out_mgr.write_log("locale_info.txt", "\n".join(locale_info), logpath)
        
    except Exception as e:
        append_error(logpath, f"collect_locale_info: {e}")
        return False

# ----------------- Registry Export -----------------
def export_registry_hives(out_mgr: OutputManager, logpath: str, config: Dict):
    if not config['logs']['registry_export'] or not config['do_reg_export']:
        return []
        
    try:
        results = []
        hives = ["HKLM", "HKU"]
        
        for hive in hives:
            target_filename = f"{hive}_export.reg"
            target_path = os.path.join(out_mgr.base_outdir, target_filename)
            tmp_path = target_path + ".tmp"
            
            try:
                rc = subprocess.call(
                    ["reg", "export", hive, tmp_path, "/y"], 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL
                )
                
                if rc == 0 and os.path.exists(tmp_path):
                    # Convert to UTF-8 with BOM
                    with open(tmp_path, 'rb') as f:
                        b = f.read()
                    
                    # Detect encoding and convert
                    if b.startswith(b'\xff\xfe') or b.startswith(b'\xfe\xff'):
                        text = b.decode('utf-16', errors='replace')
                    else:
                        try:
                            text = b.decode('utf-8')
                        except:
                            text = b.decode('cp1251', errors='replace')
                    
                    # Ensure proper header
                    if not text.lstrip().startswith("Windows Registry Editor Version"):
                        text = "Windows Registry Editor Version 5.00\r\n\r\n" + text
                    
                    write_utf8_bom(target_path, text)
                    os.remove(tmp_path)
                    results.append(target_filename)
                    out_mgr.files_created.append(target_filename)
                    
            except Exception as e:
                append_error(logpath, f"Registry export {hive} failed: {e}")
        
        return results
        
    except Exception as e:
        append_error(logpath, f"export_registry_hives: {e}")
        return []

# ----------------- Installed Programs -----------------
def collect_installed_programs(out_mgr: OutputManager, logpath: str, config: Dict) -> bool:
    if not config['logs']['installed_programs']:
        return True
        
    try:
        programs = ["=== INSTALLED PROGRAMS ==="]
        keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        
        for root, subkey in keys:
            try:
                with winreg.OpenKey(root, subkey) as key:
                    i = 0
                    while True:
                        try:
                            subname = winreg.EnumKey(key, i)
                            i += 1
                            
                            try:
                                with winreg.OpenKey(key, subname) as subkey_handle:
                                    entry = {}
                                    for vname in ("DisplayName", "DisplayVersion", 
                                                "Publisher", "InstallLocation", 
                                                "InstallDate", "UninstallString"):
                                        try:
                                            v = winreg.QueryValueEx(subkey_handle, vname)[0]
                                            if v:
                                                entry[vname] = str(v)
                                        except Exception:
                                            pass
                                    
                                    if entry.get("DisplayName"):
                                        programs.append(f"\nProgram: {entry.get('DisplayName')}")
                                        if "DisplayVersion" in entry:
                                            programs.append(f"  Version: {entry.get('DisplayVersion')}")
                                        if "Publisher" in entry:
                                            programs.append(f"  Publisher: {entry.get('Publisher')}")
                                        if "InstallLocation" in entry:
                                            programs.append(f"  Install Path: {entry.get('InstallLocation')}")
                                        if "InstallDate" in entry:
                                            programs.append(f"  Install Date: {entry.get('InstallDate')}")
                                        programs.append(f"  Registry Key: {root}\\{subkey}\\{subname}")
                                        programs.append("-" * 50)
                                        
                            except Exception:
                                pass
                                
                        except OSError:
                            break
            except FileNotFoundError:
                continue
            except Exception as e:
                programs.append(f"Error reading {root}\\{subkey}: {e}")
        
        if len(programs) == 1:
            programs.append("[No installed programs found or insufficient rights]")
        
        return out_mgr.write_log("installed_programs.txt", "\n".join(programs), logpath)
        
    except Exception as e:
        append_error(logpath, f"collect_installed_programs: {e}")
        return False

# ----------------- Main Execution -----------------
def main():
    if platform.system().lower() != "windows":
        print("This script only runs on Windows. Exiting.")
        return

    # Load configuration
    config_mgr = ConfigManager("collector_config.txt")
    config = config_mgr.load_config()
    
    # Create output directory
    host = safe_filename(socket.gethostname())
    ts = now_ts()
    base_outdir = config['output_directory'] if config['output_directory'] else os.getcwd()
    outdir = os.path.join(base_outdir, f"{host}_system_export_{ts}")
    os.makedirs(outdir, exist_ok=True)
    
    logpath = os.path.join(outdir, "collection_errors.log")
    out_mgr = OutputManager(outdir)
    
    print(f"[+] Output directory: {outdir}")
    print(f"[+] Collection started at {datetime.now()}")
    
    # Collection sequence
    collectors = [
        ("System Information", collect_system_info),
        ("OS Edition", collect_os_edition),
        ("Users and Groups", lambda: collect_users_with_groups(out_mgr, logpath, config)),
        ("User Groups SID/RID", lambda: collect_user_groups_sid_rid(out_mgr, logpath, config)),
        ("PC Characteristics", collect_pc_characteristics),
        ("Installed Programs", collect_installed_programs),
        ("Processes", collect_processes_detailed),
        ("Network Adapters", collect_network_adapters_detailed),
        ("Services", collect_services_info),
        ("Hotfixes", collect_hotfixes_list),
        ("Environment Variables", collect_environment_vars),
        ("System Uptime", collect_system_uptime),
        ("Locale Info", collect_locale_info),
    ]
    
    # Execute collectors
    for name, collector in collectors:
        if any(config['logs'].get(log_key, False) for log_key in 
              ['system_info', 'os_edition', 'users_list', 'user_groups_sid_rid', 
               'pc_characteristics', 'installed_programs', 'processes_detailed',
               'network_adapters', 'services_info', 'hotfixes_list', 
               'environment_vars', 'system_uptime', 'locale_info']):
            print(f"[+] Collecting {name}...")
            try:
                if name == "Users and Groups":
                    users = collector()
                    # Detailed user info collection
                    if config['logs']['user_detailed'] and users:
                        print("[+] Collecting detailed user information...")
                        collect_user_detailed_info(users, out_mgr, logpath, config)
                else:
                    collector(out_mgr, logpath, config)
            except Exception as e:
                append_error(logpath, f"Main collector {name}: {e}")
                print(f"[!] Error in {name}: {e}")
    
    # Registry export (special case)
    if config['logs']['registry_export'] and config['do_reg_export']:
        print("[+] Exporting registry hives...")
        reg_files = export_registry_hives(out_mgr, logpath, config)
        if reg_files:
            print(f"[+] Registry exports: {', '.join(reg_files)}")
    
    # Create manifest
    try:
        manifest = ["=== COLLECTION MANIFEST ==="]
        manifest.append(f"Collection time: {datetime.now()}")
        manifest.append(f"Hostname: {socket.gethostname()}")
        manifest.append(f"Total files: {len(out_mgr.files_created)}")
        manifest.append("\nGenerated files:")
        for file in sorted(out_mgr.files_created):
            manifest.append(f"  {file}")
        
        manifest.append("\nConfiguration used:")
        for log_key, log_enabled in config['logs'].items():
            status = "ENABLED" if log_enabled else "DISABLED"
            manifest.append(f"  {log_key}: {status}")
        
        out_mgr.write_log("manifest.txt", "\n".join(manifest), logpath)
        
    except Exception as e:
        append_error(logpath, f"Manifest creation: {e}")
    
    # Summary
    print(f"\n[+] Collection completed at {datetime.now()}")
    print(f"[+] Files created: {len(out_mgr.files_created)}")
    print(f"[+] Output directory: {outdir}")
    
    if os.path.exists(logpath) and os.path.getsize(logpath) > 0:
        print(f"[!] Errors logged: {logpath}")
    else:
        print("[+] No errors encountered")
    
    print("\n[!] Note: Some information might require administrator privileges")
    print("[!] Configure settings in 'collector_config.txt'")

if __name__ == "__main__":
    main()