#!/bin/bash

getSystemInfo() {
	hostname=$(hostname)
	uuid=$(system_profiler SPHardwareDataType | awk '/UUID/ {print $3}')
	macos_version=$(sw_vers -productVersion)
	kernel_version=$(sysctl -n kern.version)
	processor_info=$(sysctl -n machdep.cpu.brand_string)
	memory_info=$(sysctl -n hw.memsize)
	total_memory=$((memory_info/(1024*1024)))
	disk_info=$(diskutil list)
	network_info=$(ifconfig -a)
	echo ""
	echo "[*] Hostname: $hostname" 
	echo "[*] UUID: $uuid"
	echo "[*] macOS Version: $macos_version"
	echo "[*] Kernel Version: $kernel_version"
	echo "[*] Processor: $processor_info"
	echo "[*] Total Memory: $total_memory MB"
	echo "[*] Disk Info: "
	echo "$disk_info"
	echo "----------------------------"
	echo "[*] Network Info: "
	echo "$network_info"
	echo "----------------------------"
	echo ""
}

getEnv(){
	echo ""
	printenv
}

getProcessList(){
	pslist=$(ps aux)
	echo ""
	echo "$pslist"
}

getUUID() {
	ioreg -rd1 -c IOPlatformExpertDevice | grep -E '(UUID)' | awk '{ print $3; }'
}

getSystemUsers() {
	allUsersArray=()
	results=$(ls /Users | grep -v '^_')
	while read user; do
		uuid=$(dscl . -read /Users/$user GeneratedUID | awk '{print $2}')
		admin=$(dscl . -read /Groups/admin GroupMembership | grep -w "$user")
		allUsersArray+=("username: $user, uuid: $uuid, isAdmin: $admin")
	done <<< "$results"
	echo ""
	printf '%s\n' "${allUsersArray[@]}"
}

getZshHistory() {
	echo ""
	users=( $(ls /Users | grep -v '^_') )
	for user in "${users[@]}"; do
		path="/Users/$user/.zsh_history"
		if [ -f "$path" ]; then
			zsh_commands=$(<"$path")
			echo "User: $user"
			echo "ZSH commands:"
			echo "$zsh_commands"
			echo "------------------"
		fi
	done
}

getBashHistory() {
	echo ""
	users=( $(ls /Users | grep -v '^_') )
	for user in "${users[@]}"; do
		path="/Users/$user/.bash_history"
		if [ -f "$path" ]; then
			bash_commands=$(<"$path")
			echo "User: $user"
			echo "Bash commands:"
			echo "$bash_commands"
			echo "------------------"
		fi
	done
}

getShellStartupScripts() {
	echo ""
	# users=( $(dscl . -list /Users UniqueID | awk '$2 >= 500 { print $1 }') )
	users=( $(ls /Users | grep -v '^_') )
	files=(".bash_profile" ".bashrc" ".profile")
	shell_startup_scripts=()
	for user in "${users[@]}"; do
		for f in "${files[@]}"; do
			if [[ -f "/Users/$user/$f" ]]; then
			contents=$(cat "/Users/$user/$f")
			echo "User: $user"
			echo "Shell_startup_filename: $f"
			echo "Shell_startup_data:"
			echo "$contents"
			echo "---------------------------"
			fi
		done
	done
}

getPeriodic(){
	dirs=("/etc/periodic/daily" "/etc/periodic/weekly" "/etc/periodic/monthly")
	daily=()
	weekly=()
	monthly=()
	for i in "${dirs[@]}"; do
		files=($(ls "$i"))
		if [[ "$i" == "/etc/periodic/daily" ]]; then
			daily+=( "${files[@]}" )
		elif [[ "$i" == "/etc/periodic/weekly" ]]; then
			weekly+=( "${files[@]}" )
		elif [[ "$i" == "/etc/periodic/monthly" ]]; then
			monthly+=( "${files[@]}" )
		fi
	done

	periodic_scripts=(
	  "daily: ${daily[*]}"
	  "weekly: ${weekly[*]}"
	  "monthly: ${monthly[*]}"
	)

	echo ""
	printf "%s\n" "${periodic_scripts[@]}"
}

getPfRules(){
	pfrule="/etc/pf.conf"
	if [ ! -f "$pfrule" ]; then
	  echo "Error: /etc/pf.conf not found"
	  exit 1
	fi
	contents=$(cat "$pfrule")
	echo ""
	echo "$contents"
}

getSIPStatus() {
	output=$(csrutil status)
	status=$(echo "$output" | grep "System Integrity Protection status" | cut -d ':' -f2 | tr -d '.' | tr -d ' ')
	echo "status: $status"
}

getGateKeeperStatus(){
	gatekeeper_status=$(/usr/sbin/spctl --status)
	echo "$gatekeeper_status"
}

getCronJobs(){
	echo ""
	users=( $(ls /Users | grep -v '^_') )
	for user in "${users[@]}"; do
		crontab=$(crontab -u "$i" -l)
		echo "User: $user"
		echo "Crontab: $crontab"
		echo "-----------------"
	done
}

getListApps(){
	echo ""
	app_path="/Applications/"
	apps=$(ls "${app_path}")
	for app in $apps; do
	  app_full_path="${app_path}${app}"
	  echo "${app_full_path}"
	done
}

getInstallHistory(){
	echo ""
	if [ -f "/Library/Receipts/InstallHistory.plist" ]; then
		cat "/Library/Receipts/InstallHistory.plist"
	fi
}

getChromeExtensions(){
	users=( $(ls /Users | grep -v '^_') )
	for user in "${users[@]}"; do
		base_path="/Users/${user}/Library/Application Support/Google/Chrome/Default/Extensions/"
		extensions=$(ls "${base_path}")
		if [ $? -eq 0 ]; then
			for ext in $extensions; do
			  full_ext="${base_path}${ext}"
			  files=$(ls "${full_ext}")
			  for file in $files; do
				if [[ $file == "manifest.json" ]]; then
				  manifest=$(cat "${full_ext}/${file}")
				  echo "Extension path: ${full_ext}"
				  echo "Extension manifest.json content:"
				  echo "${manifest}"
				  echo "----------------------"
				fi
			  done
			done
		fi
	done
}

getActiveNetworkConnections(){
	echo ""
	echo "ProcessName ProcessID User FD IPvProtocol UniqueIdentifier TCP/UDP LocalEndpoint RemoteEndpoint"
	lsof -i -w | grep "ESTABLISHED"
}

getLaunchDaemons(){
	launchdaemons=( $(ls /Library/LaunchDaemons/ | grep 'plist') )
	echo ""
	for daemon in "${launchdaemons[@]}"; do
		echo "LaunchDaemon name: $daemon"
		cat $daemon
	done
}

getKernelExtensions(){
	echo ""
	if [ -d "/Library/Extensions/" ]; then
		for i in /Library/Extensions/*/; do
			if [ -f "${i}Contents/Info.plist" ]; then
				info_plist_data=$(cat "${i}Contents/Info.plist")
				echo "${i}"
				echo "$info_plist_data"
				echo "--------------------------------"
			fi
		done
	fi
}

# Run the functions
echo "[+] System info: $(getSystemInfo)"
echo "*****************************************************"
echo "[+] Users list: $(getSystemUsers)"
echo "*****************************************************"
echo "[+] Environment variables: $(getEnv)"
echo "*****************************************************"
echo "[+] Process list: $(getProcessList)"
echo "*****************************************************"
echo "[+] Active network connections: $(getActiveNetworkConnections)"
echo "*****************************************************"
echo "[+] SIP $(getSIPStatus)"
echo "*****************************************************"
echo "[+] GateKeeper $(getGateKeeperStatus)"
echo "*****************************************************"
echo "[+] Zsh history: $(getZshHistory)"
echo "*****************************************************"
echo "[+] Bash history: $(getBashHistory)"
echo "*****************************************************"
echo "[+] Shell startup: $(getShellStartupScripts)"
echo "*****************************************************"
echo "[+] PF rules: $(getPfRules)"
echo "*****************************************************"
echo "[+] Periodic scripts: $(getPeriodic)"
echo "*****************************************************"
echo "[+] CronJobs list: $(getCronJobs)"
echo "*****************************************************"
echo "[+] LaunchDaemons list: $(getLaunchDaemons)"
echo "*****************************************************"
echo "[+] Kernel extensions: $(getKernelExtensions)"
echo "*****************************************************"
echo "[+] Installed applications: $(getListApps)"
echo "*****************************************************"
echo "[+] Installation history: $(getInstallHistory)"
echo "*****************************************************"
echo "[+] Chrome extensions: $(getChromeExtensions)"
echo "*****************************************************"
