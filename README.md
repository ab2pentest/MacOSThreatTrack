# MacOS ThreatTrack v2.0

> Enhanced security information gathering tool for macOS systems with advanced threat detection capabilities.

## Description

MacOSThreatTrack is a comprehensive bash-based security reconnaissance tool designed for proactive detection of malicious activity on macOS systems. This enhanced version provides extensive system information gathering, threat detection capabilities, and digital forensics data collection.

Inspired by [Venator-Swift](https://github.com/richiercyrus/Venator-Swift) and enhanced with additional security features.

## Features

### 🔍 **Enhanced Information Gathering**
- **System Information**: Hostname, UUID, macOS version, kernel version, processor info, memory, disk info, network interfaces, uptime, boot time, timezone
- **User Data**: User lists with admin status, environment variables, last login information
- **Process Analysis**: Running processes, suspicious processes, high CPU processes, network processes
- **Network Information**: Active connections, listening ports, ARP table, routing table, DNS servers
- **Security Status**: SIP status, GateKeeper status, FileVault status, firewall status, automatic updates

### 🛡️ **Security & Threat Detection**
- **Threat Indicators**: Suspicious processes, connections, files, and network activity
- **File System Analysis**: Recent files, suspicious files, large files, hidden files
- **System Logs**: Error logs, authentication logs, network logs from the last hour
- **Browser Data**: Safari and Chrome bookmarks, extensions analysis

### 📊 **Output Formats**
- **JSON Output**: Structured data for automated analysis and integration
- **Text Output**: Human-readable format for manual review
- **File Export**: Save results to specified files

### 🔧 **Enhanced Features**
- **Error Handling**: Robust error handling and logging
- **Verbose Logging**: Detailed logging for debugging and analysis
- **Modular Design**: Well-organized, maintainable code structure
- **Command Line Options**: Flexible execution with various options

## Installation & Usage

### One-liner execution
```bash
curl https://raw.githubusercontent.com/ab2pentest/MacOSThreatTrack/main/MacOSThreatTrack.sh | bash
```

### Local execution
```bash
chmod +x MacOSThreatTrack.sh
./MacOSThreatTrack.sh [OPTIONS]
```

### Command Line Options
```bash
Usage: MacOSThreatTrack.sh [OPTIONS]

Options:
  -j, --json          Output in JSON format (default)
  -t, --text          Output in text format
  -o, --output FILE   Save output to file
  -v, --verbose       Enable verbose logging
  -h, --help          Show help message

Examples:
  ./MacOSThreatTrack.sh                  # Run with default JSON output
  ./MacOSThreatTrack.sh -t               # Run with text output
  ./MacOSThreatTrack.sh -o report.json   # Save JSON output to file
  ./MacOSThreatTrack.sh -v -t            # Run with verbose logging and text output
```

## Gathered Information

### System Information
- Hostname, UUID, macOS version, kernel version
- Processor information, memory details, disk information
- Network interfaces, uptime, boot time, timezone
- FileVault status, firewall status

### User & Security Data
- User lists with admin status and UUIDs
- Last login information
- Environment variables
- Security status (SIP, GateKeeper, FileVault, firewall)

### Process & Network Analysis
- All running processes
- Suspicious processes (nc, netcat, curl, wget, etc.)
- High CPU processes
- Active network connections
- Listening ports
- ARP table and routing information
- DNS server configuration

### Command History & Shell Data
- Zsh and Bash command histories for all users
- Shell startup scripts (.bash_profile, .bashrc, .profile, .zshrc)
- Recent command activity

### System Services & Applications
- Launch Daemons and Agents
- Periodic scripts
- Cron jobs
- Installed applications
- Installation history
- Chrome extensions with manifest files

### Digital Forensics Data
- Recent files (last 7 days)
- Suspicious files (.exe, .bat, .cmd, .scr)
- Large files (>100MB)
- Hidden files
- System logs (errors, authentication, network)
- Browser bookmarks (Safari, Chrome)

### Threat Detection
- Suspicious processes and connections
- Suspicious files and network activity
- Indicators of compromise
- Recent network activity patterns

## JSON Output Structure

```json
{
  "metadata": {
    "tool": "MacOSThreatTrack",
    "version": "2.0",
    "timestamp": "2024-01-01T12:00:00Z",
    "hostname": "MacBook-Pro",
    "user": "admin"
  },
  "data": {
    "system_info": { ... },
    "users": { ... },
    "processes": { ... },
    "network": { ... },
    "security": { ... },
    "command_history": { ... },
    "shell_scripts": { ... },
    "system_services": { ... },
    "applications": { ... },
    "file_system": { ... },
    "system_logs": { ... },
    "browser_data": { ... },
    "threat_indicators": { ... }
  }
}
```

## Use Cases

- **Security Assessments**: Comprehensive system security evaluation
- **Incident Response**: Rapid information gathering during security incidents
- **Threat Hunting**: Proactive detection of malicious activity
- **Digital Forensics**: Evidence collection and analysis
- **Compliance Auditing**: Security posture assessment
- **System Monitoring**: Baseline establishment and change detection

## Requirements

- macOS system
- Bash shell
- Standard macOS utilities (system_profiler, sw_vers, sysctl, etc.)
- Some features may require sudo privileges

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

This project is open source and available under the MIT License.
