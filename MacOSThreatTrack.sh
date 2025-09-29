#!/bin/bash

# MacOSThreatTrack - Enhanced Security Information Gathering Tool
# Version: 2.0
# Author: Enhanced version with additional security features

set -euo pipefail

# Global variables
SCRIPT_VERSION="2.0"
OUTPUT_FORMAT="json"
OUTPUT_FILE=""
VERBOSE=false
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO") echo -e "${GREEN}[INFO]${NC} $message" ;;
        "WARN") echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
        "DEBUG") [[ $VERBOSE == true ]] && echo -e "${BLUE}[DEBUG]${NC} $message" ;;
    esac
}

# JSON helper functions
json_start() {
    echo "{"
    echo "  \"metadata\": {"
    echo "    \"tool\": \"MacOSThreatTrack\","
    echo "    \"version\": \"$SCRIPT_VERSION\","
    echo "    \"timestamp\": \"$TIMESTAMP\","
    echo "    \"hostname\": \"$(hostname)\","
    echo "    \"user\": \"$(whoami)\""
    echo "  },"
    echo "  \"data\": {"
}

json_end() {
    echo "  }"
    echo "}"
}

json_section() {
    local section_name="$1"
    echo "    \"$section_name\": {"
}

json_section_end() {
    echo "    }"
}

json_key_value() {
    local key="$1"
    local value="$2"
    echo "      \"$key\": \"$value\""
}

json_key_value_no_quote() {
    local key="$1"
    local value="$2"
    echo "      \"$key\": $value"
}

# Enhanced system information gathering
getSystemInfo() {
    log "INFO" "Gathering system information..."
    
    local hostname=$(hostname)
    local uuid=$(system_profiler SPHardwareDataType 2>/dev/null | awk '/UUID/ {print $3}' || echo "unknown")
    local macos_version=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
    local kernel_version=$(sysctl -n kern.version 2>/dev/null || echo "unknown")
    local processor_info=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown")
    local memory_info=$(sysctl -n hw.memsize 2>/dev/null || echo "0")
    local total_memory=$((memory_info/(1024*1024)))
    local uptime=$(uptime 2>/dev/null || echo "unknown")
    local boot_time=$(sysctl -n kern.boottime 2>/dev/null | awk '{print $4}' | sed 's/,//' || echo "unknown")
    local timezone=$(systemsetup -gettimezone 2>/dev/null | cut -d' ' -f3 || echo "unknown")
    
    # Disk information
    local disk_info=$(diskutil list -plist 2>/dev/null | plutil -convert json - - 2>/dev/null || echo "{}")
    local network_info=$(ifconfig -a 2>/dev/null || echo "unknown")
    
    # Security features
    local filevault_status=$(fdesetup status 2>/dev/null || echo "unknown")
    local firewall_status=$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
    
    if [[ $OUTPUT_FORMAT == "json" ]]; then
        json_section "system_info"
        json_key_value "hostname" "$hostname"
        json_key_value "uuid" "$uuid"
        json_key_value "macos_version" "$macos_version"
        json_key_value "kernel_version" "$kernel_version"
        json_key_value "processor" "$processor_info"
        json_key_value_no_quote "total_memory_mb" "$total_memory"
        json_key_value "uptime" "$uptime"
        json_key_value "boot_time" "$boot_time"
        json_key_value "timezone" "$timezone"
        json_key_value "filevault_status" "$filevault_status"
        json_key_value "firewall_status" "$firewall_status"
        json_key_value_no_quote "disk_info" "$disk_info"
        json_key_value "network_info" "$network_info"
        json_section_end
    else
        echo ""
        echo "[*] Hostname: $hostname"
        echo "[*] UUID: $uuid"
        echo "[*] macOS Version: $macos_version"
        echo "[*] Kernel Version: $kernel_version"
        echo "[*] Processor: $processor_info"
        echo "[*] Total Memory: $total_memory MB"
        echo "[*] Uptime: $uptime"
        echo "[*] Boot Time: $boot_time"
        echo "[*] Timezone: $timezone"
        echo "[*] FileVault Status: $filevault_status"
        echo "[*] Firewall Status: $firewall_status"
        echo "[*] Disk Info: $disk_info"
        echo "[*] Network Info: $network_info"
    fi
}

# Enhanced user information
getSystemUsers() {
    log "INFO" "Gathering user information..."
    
    local users=($(dscl . -list /Users UniqueID 2>/dev/null | awk '$2 >= 500 { print $1 }' || echo ""))
    local current_user=$(whoami)
    local last_login=$(last -1 2>/dev/null | head -1 || echo "unknown")
    
    if [[ $OUTPUT_FORMAT == "json" ]]; then
        json_section "users"
        json_key_value "current_user" "$current_user"
        json_key_value "last_login" "$last_login"
        echo "      \"user_list\": ["
        
        local first=true
        for user in "${users[@]}"; do
            if [[ $first == true ]]; then
                first=false
            else
                echo ","
            fi
            
            local uuid=$(dscl . -read /Users/$user GeneratedUID 2>/dev/null | awk '{print $2}' || echo "unknown")
            local admin=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | grep -w "$user" >/dev/null && echo "true" || echo "false")
            local home_dir=$(dscl . -read /Users/$user NFSHomeDirectory 2>/dev/null | awk '{print $2}' || echo "unknown")
            local shell=$(dscl . -read /Users/$user UserShell 2>/dev/null | awk '{print $2}' || echo "unknown")
            local last_login_user=$(last -1 "$user" 2>/dev/null | head -1 || echo "unknown")
            
            echo "        {"
            json_key_value "username" "$user"
            json_key_value "uuid" "$uuid"
            json_key_value_no_quote "is_admin" "$admin"
            json_key_value "home_directory" "$home_dir"
            json_key_value "shell" "$shell"
            json_key_value "last_login" "$last_login_user"
            echo -n "        }"
        done
        echo ""
        echo "      ]"
        json_section_end
    else
        echo ""
        echo "[*] Current User: $current_user"
        echo "[*] Last Login: $last_login"
        echo "[*] Users:"
        for user in "${users[@]}"; do
            local uuid=$(dscl . -read /Users/$user GeneratedUID 2>/dev/null | awk '{print $2}' || echo "unknown")
            local admin=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | grep -w "$user" >/dev/null && echo "true" || echo "false")
            echo "  - $user (UUID: $uuid, Admin: $admin)"
        done
    fi
}

# Enhanced process information with security focus
getProcessList() {
    log "INFO" "Gathering process information..."
    
    local processes=$(ps aux 2>/dev/null || echo "")
    local suspicious_processes=$(ps aux 2>/dev/null | grep -E "(nc|netcat|ncat|socat|curl|wget|python|perl|ruby|php|bash|sh|zsh|powershell)" | grep -v grep || echo "")
    local high_cpu_processes=$(ps aux 2>/dev/null | sort -nrk 3,3 | head -10 || echo "")
    local network_processes=$(lsof -i 2>/dev/null | awk '{print $1, $2, $5, $9}' | sort -u || echo "")
    
    if [[ $OUTPUT_FORMAT == "json" ]]; then
        json_section "processes"
        json_key_value "all_processes" "$processes"
        json_key_value "suspicious_processes" "$suspicious_processes"
        json_key_value "high_cpu_processes" "$high_cpu_processes"
        json_key_value "network_processes" "$network_processes"
        json_section_end
    else
        echo ""
        echo "[*] All Processes:"
        echo "$processes"
        echo ""
        echo "[*] Suspicious Processes:"
        echo "$suspicious_processes"
        echo ""
        echo "[*] High CPU Processes:"
        echo "$high_cpu_processes"
        echo ""
        echo "[*] Network Processes:"
        echo "$network_processes"
    fi
}

# Enhanced network information
getNetworkInfo() {
    log "INFO" "Gathering network information..."
    
    local active_connections=$(lsof -i -w 2>/dev/null | grep "ESTABLISHED" || echo "")
    local listening_ports=$(lsof -i -w 2>/dev/null | grep "LISTEN" || echo "")
    local arp_table=$(arp -a 2>/dev/null || echo "")
    local routing_table=$(netstat -rn 2>/dev/null || echo "")
    local dns_servers=$(scutil --dns 2>/dev/null | grep nameserver || echo "")
    local network_interfaces=$(ifconfig -a 2>/dev/null || echo "")
    
    if [[ $OUTPUT_FORMAT == "json" ]]; then
        json_section "network"
        json_key_value "active_connections" "$active_connections"
        json_key_value "listening_ports" "$listening_ports"
        json_key_value "arp_table" "$arp_table"
        json_key_value "routing_table" "$routing_table"
        json_key_value "dns_servers" "$dns_servers"
        json_key_value "network_interfaces" "$network_interfaces"
        json_section_end
    else
        echo ""
        echo "[*] Active Connections:"
        echo "$active_connections"
        echo ""
        echo "[*] Listening Ports:"
        echo "$listening_ports"
        echo ""
        echo "[*] ARP Table:"
        echo "$arp_table"
        echo ""
        echo "[*] Routing Table:"
        echo "$routing_table"
        echo ""
        echo "[*] DNS Servers:"
        echo "$dns_servers"
    fi
}

# Enhanced security status
getSecurityStatus() {
    log "INFO" "Gathering security status..."
    
    local sip_status=$(csrutil status 2>/dev/null | grep "System Integrity Protection status" | cut -d ':' -f2 | tr -d '.' | tr -d ' ' || echo "unknown")
    local gatekeeper_status=$(/usr/sbin/spctl --status 2>/dev/null || echo "unknown")
    local quarantine_status=$(defaults read com.apple.LaunchServices LSQuarantine 2>/dev/null || echo "unknown")
    local filevault_status=$(fdesetup status 2>/dev/null || echo "unknown")
    local firewall_status=$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
    local automatic_updates=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "unknown")
    
    if [[ $OUTPUT_FORMAT == "json" ]]; then
        json_section "security"
        json_key_value "sip_status" "$sip_status"
        json_key_value "gatekeeper_status" "$gatekeeper_status"
        json_key_value "quarantine_status" "$quarantine_status"
        json_key_value "filevault_status" "$filevault_status"
        json_key_value "firewall_status" "$firewall_status"
        json_key_value "automatic_updates" "$automatic_updates"
        json_section_end
    else
        echo ""
        echo "[*] SIP Status: $sip_status"
        echo "[*] GateKeeper Status: $gatekeeper_status"
        echo "[*] Quarantine Status: $quarantine_status"
        echo "[*] FileVault Status: $filevault_status"
        echo "[*] Firewall Status: $firewall_status"
        echo "[*] Automatic Updates: $automatic_updates"
    fi
}

# Enhanced command history with timestamps
getCommandHistory() {
    log "INFO" "Gathering command history..."
    
    local users=($(ls /Users 2>/dev/null | grep -v '^_' || echo ""))
    
    if [[ $OUTPUT_FORMAT == "json" ]]; then
        json_section "command_history"
        echo "      \"histories\": ["
        
        local first_user=true
        for user in "${users[@]}"; do
            if [[ $first_user == true ]]; then
                first_user=false
            else
                echo ","
            fi
            
            echo "        {"
            json_key_value "user" "$user"
            
            # Zsh history
            local zsh_path="/Users/$user/.zsh_history"
            if [[ -f "$zsh_path" ]]; then
                local zsh_commands=$(cat "$zsh_path" 2>/dev/null || echo "")
                json_key_value "zsh_history" "$zsh_commands"
            else
                json_key_value "zsh_history" "not_found"
            fi
            
            # Bash history
            local bash_path="/Users/$user/.bash_history"
            if [[ -f "$bash_path" ]]; then
                local bash_commands=$(cat "$bash_path" 2>/dev/null || echo "")
                json_key_value "bash_history" "$bash_commands"
            else
                json_key_value "bash_history" "not_found"
            fi
            
            echo -n "        }"
        done
        echo ""
        echo "      ]"
        json_section_end
    else
        echo ""
        for user in "${users[@]}"; do
            echo "[*] User: $user"
            
            local zsh_path="/Users/$user/.zsh_history"
            if [[ -f "$zsh_path" ]]; then
                echo "ZSH History:"
                cat "$zsh_path" 2>/dev/null || echo "Error reading zsh history"
            fi
            
            local bash_path="/Users/$user/.bash_history"
            if [[ -f "$bash_path" ]]; then
                echo "Bash History:"
                cat "$bash_path" 2>/dev/null || echo "Error reading bash history"
            fi
            echo "------------------"
        done
    fi
}

# Enhanced shell startup scripts
getShellStartupScripts() {
    log "INFO" "Gathering shell startup scripts..."
    
    local users=($(ls /Users 2>/dev/null | grep -v '^_' || echo ""))
    local files=(".bash_profile" ".bashrc" ".profile" ".zshrc" ".zprofile")
    
    if [[ $OUTPUT_FORMAT == "json" ]]; then
        json_section "shell_scripts"
        echo "      \"scripts\": ["
        
        local first_user=true
        for user in "${users[@]}"; do
            for file in "${files[@]}"; do
                local file_path="/Users/$user/$file"
                if [[ -f "$file_path" ]]; then
                    if [[ $first_user == true ]]; then
                        first_user=false
                    else
                        echo ","
                    fi
                    
                    local contents=$(cat "$file_path" 2>/dev/null || echo "")
                    echo "        {"
                    json_key_value "user" "$user"
                    json_key_value "filename" "$file"
                    json_key_value "content" "$contents"
                    echo -n "        }"
                fi
            done
        done
        echo ""
        echo "      ]"
        json_section_end
    else
        echo ""
        for user in "${users[@]}"; do
            for file in "${files[@]}"; do
                local file_path="/Users/$user/$file"
                if [[ -f "$file_path" ]]; then
                    echo "User: $user, File: $file"
                    cat "$file_path" 2>/dev/null || echo "Error reading file"
                    echo "---------------------------"
                fi
            done
        done
    fi
}

# Enhanced system services and daemons
getSystemServices() {
    log "INFO" "Gathering system services..."
    
    local launchdaemons=$(ls /Library/LaunchDaemons/ 2>/dev/null | grep 'plist' || echo "")
    local launchagents=$(ls /Library/LaunchAgents/ 2>/dev/null | grep 'plist' || echo "")
    local user_launchagents=$(ls ~/Library/LaunchAgents/ 2>/dev/null | grep 'plist' || echo "")
    local periodic_scripts=$(find /etc/periodic -type f 2>/dev/null || echo "")
    local cron_jobs=$(crontab -l 2>/dev/null || echo "no_cron_jobs")
    
    if [[ $OUTPUT_FORMAT == "json" ]]; then
        json_section "system_services"
        json_key_value "launch_daemons" "$launchdaemons"
        json_key_value "launch_agents" "$launchagents"
        json_key_value "user_launch_agents" "$user_launchagents"
        json_key_value "periodic_scripts" "$periodic_scripts"
        json_key_value "cron_jobs" "$cron_jobs"
        json_section_end
    else
        echo ""
        echo "[*] Launch Daemons:"
        echo "$launchdaemons"
        echo ""
        echo "[*] Launch Agents:"
        echo "$launchagents"
        echo ""
        echo "[*] User Launch Agents:"
        echo "$user_launchagents"
        echo ""
        echo "[*] Periodic Scripts:"
        echo "$periodic_scripts"
        echo ""
        echo "[*] Cron Jobs:"
        echo "$cron_jobs"
    fi
}

# Enhanced application information
getApplicationInfo() {
    log "INFO" "Gathering application information..."
    
    local installed_apps=$(ls /Applications/ 2>/dev/null || echo "")
    local install_history=""
    if [[ -f "/Library/Receipts/InstallHistory.plist" ]]; then
        install_history=$(cat "/Library/Receipts/InstallHistory.plist" 2>/dev/null || echo "")
    fi
    local chrome_extensions=""
    local users=($(ls /Users 2>/dev/null | grep -v '^_' || echo ""))
    
    # Chrome extensions
    for user in "${users[@]}"; do
        local base_path="/Users/${user}/Library/Application Support/Google/Chrome/Default/Extensions/"
        if [[ -d "$base_path" ]]; then
            local extensions=$(ls "$base_path" 2>/dev/null || echo "")
            chrome_extensions="$chrome_extensions\nUser: $user\nExtensions: $extensions"
        fi
    done
    
    if [[ $OUTPUT_FORMAT == "json" ]]; then
        json_section "applications"
        json_key_value "installed_apps" "$installed_apps"
        json_key_value "install_history" "$install_history"
        json_key_value "chrome_extensions" "$chrome_extensions"
        json_section_end
    else
        echo ""
        echo "[*] Installed Applications:"
        echo "$installed_apps"
        echo ""
        echo "[*] Installation History:"
        echo "$install_history"
        echo ""
        echo "[*] Chrome Extensions:"
        echo -e "$chrome_extensions"
    fi
}

# New: File system analysis
getFileSystemAnalysis() {
    log "INFO" "Gathering file system analysis..."
    
    local recent_files=$(find /Users -name ".*" -type f -mtime -7 2>/dev/null | head -50 || echo "")
    local suspicious_files=$(find /Users -name "*.exe" -o -name "*.bat" -o -name "*.cmd" -o -name "*.scr" 2>/dev/null || echo "")
    local large_files=$(find /Users -type f -size +100M 2>/dev/null | head -20 || echo "")
    local hidden_files=$(find /Users -name ".*" -type f 2>/dev/null | head -50 || echo "")
    
    if [[ $OUTPUT_FORMAT == "json" ]]; then
        json_section "file_system"
        json_key_value "recent_files" "$recent_files"
        json_key_value "suspicious_files" "$suspicious_files"
        json_key_value "large_files" "$large_files"
        json_key_value "hidden_files" "$hidden_files"
        json_section_end
    else
        echo ""
        echo "[*] Recent Files (last 7 days):"
        echo "$recent_files"
        echo ""
        echo "[*] Suspicious Files:"
        echo "$suspicious_files"
        echo ""
        echo "[*] Large Files (>100MB):"
        echo "$large_files"
        echo ""
        echo "[*] Hidden Files:"
        echo "$hidden_files"
    fi
}

# New: System logs analysis
getSystemLogs() {
    log "INFO" "Gathering system logs..."
    
    local system_logs=$(log show --last 1h --predicate 'eventMessage contains "error" or eventMessage contains "failed" or eventMessage contains "denied"' 2>/dev/null | head -50 || echo "")
    local auth_logs=$(log show --last 1h --predicate 'process == "loginwindow" or process == "sudo"' 2>/dev/null | head -50 || echo "")
    local network_logs=$(log show --last 1h --predicate 'eventMessage contains "network" or eventMessage contains "connection"' 2>/dev/null | head -50 || echo "")
    
    if [[ $OUTPUT_FORMAT == "json" ]]; then
        json_section "system_logs"
        json_key_value "error_logs" "$system_logs"
        json_key_value "auth_logs" "$auth_logs"
        json_key_value "network_logs" "$network_logs"
        json_section_end
    else
        echo ""
        echo "[*] System Error Logs (last hour):"
        echo "$system_logs"
        echo ""
        echo "[*] Authentication Logs (last hour):"
        echo "$auth_logs"
        echo ""
        echo "[*] Network Logs (last hour):"
        echo "$network_logs"
    fi
}

# New: Browser data analysis
getBrowserData() {
    log "INFO" "Gathering browser data..."
    
    local users=($(ls /Users 2>/dev/null | grep -v '^_' || echo ""))
    local browser_data=""
    
    for user in "${users[@]}"; do
        # Safari bookmarks
        local safari_bookmarks=""
        if [[ -f "/Users/$user/Library/Safari/Bookmarks.plist" ]]; then
            safari_bookmarks=$(plutil -convert json "/Users/$user/Library/Safari/Bookmarks.plist" - - 2>/dev/null || echo "")
        fi
        
        # Chrome bookmarks
        local chrome_bookmarks=""
        if [[ -f "/Users/$user/Library/Application Support/Google/Chrome/Default/Bookmarks" ]]; then
            chrome_bookmarks=$(cat "/Users/$user/Library/Application Support/Google/Chrome/Default/Bookmarks" 2>/dev/null || echo "")
        fi
        
        browser_data="$browser_data\nUser: $user\nSafari Bookmarks: $safari_bookmarks\nChrome Bookmarks: $chrome_bookmarks"
    done
    
    if [[ $OUTPUT_FORMAT == "json" ]]; then
        json_section "browser_data"
        json_key_value "data" "$browser_data"
        json_section_end
    else
        echo ""
        echo "[*] Browser Data:"
        echo -e "$browser_data"
    fi
}

# New: Threat indicators
getThreatIndicators() {
    log "INFO" "Analyzing threat indicators..."
    
    local suspicious_processes=$(ps aux 2>/dev/null | grep -E "(nc|netcat|ncat|socat|curl|wget|python|perl|ruby|php|bash|sh|zsh|powershell)" | grep -v grep || echo "")
    local suspicious_connections=$(lsof -i 2>/dev/null | grep -E "(ESTABLISHED|LISTEN)" | grep -E "(nc|netcat|ncat|socat|curl|wget)" || echo "")
    local suspicious_files=$(find /Users -name "*.exe" -o -name "*.bat" -o -name "*.cmd" -o -name "*.scr" 2>/dev/null || echo "")
    local recent_network_activity=$(netstat -rn 2>/dev/null | grep -E "(0.0.0.0|127.0.0.1)" || echo "")
    
    if [[ $OUTPUT_FORMAT == "json" ]]; then
        json_section "threat_indicators"
        json_key_value "suspicious_processes" "$suspicious_processes"
        json_key_value "suspicious_connections" "$suspicious_connections"
        json_key_value "suspicious_files" "$suspicious_files"
        json_key_value "recent_network_activity" "$recent_network_activity"
        json_section_end
    else
        echo ""
        echo "[*] Suspicious Processes:"
        echo "$suspicious_processes"
        echo ""
        echo "[*] Suspicious Connections:"
        echo "$suspicious_connections"
        echo ""
        echo "[*] Suspicious Files:"
        echo "$suspicious_files"
        echo ""
        echo "[*] Recent Network Activity:"
        echo "$recent_network_activity"
    fi
}

# Usage function
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -j, --json          Output in JSON format (default)"
    echo "  -t, --text          Output in text format"
    echo "  -o, --output FILE   Save output to file"
    echo "  -v, --verbose       Enable verbose logging"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                  # Run with default JSON output"
    echo "  $0 -t               # Run with text output"
    echo "  $0 -o report.json   # Save JSON output to file"
    echo "  $0 -v -t            # Run with verbose logging and text output"
}

# Main execution function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -j|--json)
                OUTPUT_FORMAT="json"
                shift
                ;;
            -t|--text)
                OUTPUT_FORMAT="text"
                shift
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    log "INFO" "Starting MacOSThreatTrack v$SCRIPT_VERSION"
    log "INFO" "Output format: $OUTPUT_FORMAT"
    
    if [[ $OUTPUT_FORMAT == "json" ]]; then
        json_start
        getSystemInfo
        echo ","
        getSystemUsers
        echo ","
        getProcessList
        echo ","
        getNetworkInfo
        echo ","
        getSecurityStatus
        echo ","
        getCommandHistory
        echo ","
        getShellStartupScripts
        echo ","
        getSystemServices
        echo ","
        getApplicationInfo
        echo ","
        getFileSystemAnalysis
        echo ","
        getSystemLogs
        echo ","
        getBrowserData
        echo ","
        getThreatIndicators
        json_end
    else
        echo "=========================================="
        echo "MacOSThreatTrack v$SCRIPT_VERSION"
        echo "Timestamp: $TIMESTAMP"
        echo "=========================================="
        
        getSystemInfo
        echo "*****************************************************"
        getSystemUsers
        echo "*****************************************************"
        getProcessList
        echo "*****************************************************"
        getNetworkInfo
        echo "*****************************************************"
        getSecurityStatus
        echo "*****************************************************"
        getCommandHistory
        echo "*****************************************************"
        getShellStartupScripts
        echo "*****************************************************"
        getSystemServices
        echo "*****************************************************"
        getApplicationInfo
        echo "*****************************************************"
        getFileSystemAnalysis
        echo "*****************************************************"
        getSystemLogs
        echo "*****************************************************"
        getBrowserData
        echo "*****************************************************"
        getThreatIndicators
        echo "*****************************************************"
    fi
    
    if [[ -n "$OUTPUT_FILE" ]]; then
        log "INFO" "Saving output to: $OUTPUT_FILE"
    fi
    
    log "INFO" "MacOSThreatTrack completed successfully"
}

# Run main function with all arguments
main "$@"