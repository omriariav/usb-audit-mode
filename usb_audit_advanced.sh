#!/bin/bash

# ----------------------------------------
# usb_audit.sh – USB Audit Mode for macOS (Critic Mode Enhanced)
# ----------------------------------------
# Monitors USB plug-ins, network activity, and suspicious system behaviors
# Optional: Use --advanced flag to enable deeper checks (for rubber ducky & malware-like behavior)
# ----------------------------------------

ADVANCED=false
if [[ "$1" == "--advanced" ]]; then
  ADVANCED=true
  echo "🔍 Advanced mode enabled: will check for process injection, malware artifacts, and spoofing attempts"
fi

timestamp=$(date +"%Y%m%d_%H%M%S")
log_file="usb_audit_log_${timestamp}.txt"
echo "🔌 USB Audit Mode Started: $(date)" | tee -a "$log_file"

baseline_netstat=$(netstat -an | grep ESTABLISHED | sort)

while true; do
  usb_event=$(log show --style syslog --predicate 'eventMessage CONTAINS "USB"' --last 1s | grep -i "USB")

  if [[ -n "$usb_event" ]]; then
    echo "⚠️  USB device connected: $(date)" | tee -a "$log_file"
    echo "$usb_event" | tee -a "$log_file"

    echo "🧪 USB Device Snapshot (ioreg):" | tee -a "$log_file"
    ioreg -p IOUSB -l | grep -E "Product|Vendor|Serial|Current" | tee -a "$log_file"

    echo "🧾 USB Device Classes (system_profiler):" | tee -a "$log_file"
    system_profiler SPUSBDataType | tee -a "$log_file"

    echo "⏳ Waiting 10 seconds to observe network activity..." | tee -a "$log_file"
    sleep 10

    new_netstat=$(netstat -an | grep ESTABLISHED | sort)
    new_connections=$(comm -13 <(echo "$baseline_netstat") <(echo "$new_netstat"))

    if [[ -n "$new_connections" ]]; then
      echo "🔍 New network connections:" | tee -a "$log_file"
      echo "$new_connections" | tee -a "$log_file"
      echo | tee -a "$log_file"

      echo "🔎 Resolving responsible processes:" | tee -a "$log_file"
      echo "$new_connections" | awk '{print $5}' | cut -d. -f1-4 | sort | uniq | while read ip; do
        hostname=$(dig +short -x "$ip" | sed 's/\.$//')
        if [[ -z "$hostname" ]]; then hostname="(no reverse DNS)"; fi
        echo "➡️  $ip [$hostname]" | tee -a "$log_file"

        lsof_output=$(lsof -nP -i "@$ip" 2>/dev/null)
        if [[ -n "$lsof_output" ]]; then
          echo "$lsof_output" | tee -a "$log_file"
        else
          echo "⚠️  No process found (connection may have closed)" | tee -a "$log_file"
        fi
        echo | tee -a "$log_file"
      done
    else
      echo "✅ No new network connections detected." | tee -a "$log_file"
    fi

    baseline_netstat=$new_netstat

    if [ "$ADVANCED" = true ]; then
      echo "🛡️ Running advanced checks..." | tee -a "$log_file"

      echo "📁 Recently modified LaunchAgents:" | tee -a "$log_file"
      find ~/Library/LaunchAgents -type f -mmin -5 2>/dev/null | tee -a "$log_file"

      echo "🧯 Recent Terminal activity (log):" | tee -a "$log_file"
      log show --predicate 'processImagePath CONTAINS "Terminal"' --last 30s | tee -a "$log_file"

      echo "📝 Recent login items:" | tee -a "$log_file"
      osascript -e 'tell application "System Events" to get the name of every login item' | tee -a "$log_file"

      echo "🧠 Suspicious shell history (curl/wget/sudo):" | tee -a "$log_file"
      grep -E 'curl|wget|osascript|sudo' ~/.zsh_history 2>/dev/null | tail -n 5 | tee -a "$log_file"
    fi

    echo "📡 Audit continues..." | tee -a "$log_file"
  fi

  sleep 1
done
