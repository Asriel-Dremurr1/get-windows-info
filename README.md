# get-windows-info
Programm for get Windows and some PC info

# Enhanced System Information Collector

A comprehensive Windows system information collection tool that uses only Python standard libraries (ctypes + winreg) without relying on external Windows CLI utilities. Fully configurable with enable/disable options for each log type.

## Features

### 🔍 **System Information**
- Hostname, platform, and architecture details
- OS edition and license information
- System uptime and installation date
- Locale and regional settings

### 👥 **User Management**
- Local user accounts enumeration
- User home directory analysis
- SID/RID information
- Detailed user folder statistics

### 💻 **Hardware Information**
- Processor details and core count
- Memory usage and statistics
- Disk drives and storage analysis
- Network adapter configuration

### 🛠️ **Software & Services**
- Installed programs list
- Running processes with details
- Windows services information
- Installed updates and hotfixes

### ⚙️ **Advanced Features**
- Environment variables
- Registry export (requires admin)
- Configurable collection modules
- UTF-8 output with BOM

## Requirements
- **OS**: Windows 7/8/10/11, Windows Server
- **Permissions**: Standard user (some features require admin rights)

### A separate program for analyzing the list of installed programs by keywords
