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
  echo "🔍 Advanced mode enabled: will check for process injection, malware artifacts, and spoofing attempts" | tee -a "$log_file"
fi

timestamp=$(date +"%Y%m%d_%H%M%S")
log_file="usb_audit_log_${timestamp}.txt"
echo "🔌 USB Audit Mode Started: $(date)" | tee -a "$log_file"
echo "🔍 Monitoring for USB plug-ins, network activity, and suspicious behaviors..." | tee -a "$log_file"

baseline_netstat=$(netstat -an | grep ESTABLISHED | sort)

while true; do
  usb_event=$(log show --style syslog --predicate 'eventMessage CONTAINS "USB"' --last 1s | grep -i "USB")

  if [[ -n "$usb_event" ]]; then
    echo "⚠️  USB device connected: $(date)" | tee -a "$log_file"
    echo "🔍 USB event detected, logging details..." | tee -a "$log_file"
    echo "$usb_event" | tee -a "$log_file"

    echo "🧪 USB Device Snapshot (ioreg):" | tee -a "$log_file"
    echo "🔍 Gathering USB device information..." | tee -a "$log_file"
    ioreg -p IOUSB -l | grep -E "Product|Vendor|Serial|Current" | tee -a "$log_file"

    # Check for red flags in USB device information
    ioreg -p IOUSB -l | grep -E "Product|Vendor|Serial|Current" | while read line; do
      if echo "$line" | grep -q "Current" && echo "$line" | grep -qE "[5-9][0-9]{2}|[1-9][0-9]{3,}"; then
        echo "🚩 Red Flag: Device drawing more than 500mA!" | tee -a "$log_file"
      fi
      if echo "$line" | grep -q "Vendor" && echo "$line" | grep -q "Unknown"; then
        echo "🚩 Red Flag: Device with no vendor ID!" | tee -a "$log_file"
      fi
      if echo "$line" | grep -q "Product" && echo "$line" | grep -q "Unknown"; then
        echo "🚩 Red Flag: Device with no product ID!" | tee -a "$log_file"
      fi
    done

    echo "🧾 USB Device Classes (system_profiler):" | tee -a "$log_file"
    echo "🔍 Gathering USB device class information..." | tee -a "$log_file"
    system_profiler SPUSBDataType | tee -a "$log_file"

    echo "⏳ Waiting 10 seconds to observe network activity..." | tee -a "$log_file"
    sleep 10

    new_netstat=$(netstat -an | grep ESTABLISHED | sort)
    new_connections=$(comm -13 <(echo "$baseline_netstat") <(echo "$new_netstat"))

    if [[ -n "$new_connections" ]]; then
      echo "🔍 New network connections detected:" | tee -a "$log_file"
      echo "$new_connections" | tee -a "$log_file"
      echo | tee -a "$log_file"

      echo "🔎 Resolving responsible processes for new connections:" | tee -a "$log_file"
      echo "$new_connections" | awk '{print $5}' | cut -d. -f1-4 | sort | uniq | while read ip; do
        hostname=$(dig +short -x "$ip" | sed 's/\.$//')
        if [[ -z "$hostname" ]]; then hostname="(no reverse DNS)"; fi
        echo "➡️  $ip [$hostname]" | tee -a "$log_file"

        lsof_output=$(lsof -nP -i "@$ip" 2>/dev/null)
        if [[ -n "$lsof_output" ]]; then
          echo "$lsof_output" | tee -a "$log_file"
        else
          echo "⚠️  No process found (connection may have closed)" | tee -a "$log_file"
          echo "🚩 Red Flag: Connection to unknown IP with no matching process!" | tee -a "$log_file"
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
      echo "🔍 Checking for recently modified LaunchAgents..." | tee -a "$log_file"
      find ~/Library/LaunchAgents -type f -mmin -5 2>/dev/null | tee -a "$log_file"

      echo "🧯 Recent Terminal activity (log):" | tee -a "$log_file"
      echo "🔍 Checking for recent Terminal activity..." | tee -a "$log_file"
      log show --predicate 'processImagePath CONTAINS "Terminal"' --last 30s | tee -a "$log_file"

      echo "📝 Recent login items:" | tee -a "$log_file"
      echo "🔍 Listing recent login items..." | tee -a "$log_file"
      osascript -e 'tell application "System Events" to get the name of every login item' | tee -a "$log_file"

      echo "🧠 Suspicious shell history (curl/wget/sudo):" | tee -a "$log_file"
      echo "🔍 Checking for suspicious shell history..." | tee -a "$log_file"
      grep -E 'curl|wget|osascript|sudo' ~/.zsh_history 2>/dev/null | tail -n 5 | tee -a "$log_file"
      if grep -E 'curl|wget|osascript|sudo' ~/.zsh_history 2>/dev/null | tail -n 5 | grep -qE 'curl|wget|osascript|sudo'; then
        echo "🚩 Red Flag: Suspicious shell command executed after USB plug-in!" | tee -a "$log_file"
      fi
    fi

    echo "📡 Audit continues..." | tee -a "$log_file"
  fi

  sleep 1
done
