#!/bin/bash

# ----------------------------------------
# usb_audit.sh – USB Audit Mode for macOS
# ----------------------------------------
# Monitors for USB plug-ins and logs:
# - USB device info (product, vendor, power draw)
# - New outbound network connections post-plug-in
# - Reverse DNS of remote IPs
# - Responsible local processes (if any)
# ----------------------------------------

# Create a timestamped log file for each run
timestamp=$(date +"%Y%m%d_%H%M%S")
log_file="usb_audit_log_${timestamp}.txt"

echo "🔌 USB Audit Mode Started: $(date)" | tee -a "$log_file"

# Capture initial baseline of current network connections
baseline_netstat=$(netstat -an | grep ESTABLISHED | sort)

# Main loop - checks for new USB events every second
while true; do
  # Detect USB plug-in events using macOS unified logs
  usb_event=$(log show --style syslog --predicate 'eventMessage CONTAINS "USB"' --last 1s | grep -i "USB")

  if [[ -n "$usb_event" ]]; then
    echo "⚠️  USB device connected: $(date)" | tee -a "$log_file"
    echo "$usb_event" | tee -a "$log_file"

    # Log current USB device snapshot including power draw
    echo "🧪 USB Device Snapshot (ioreg):" | tee -a "$log_file"
    ioreg -p IOUSB -l | grep -E "Product|Vendor|Serial|Current" | tee -a "$log_file"

    echo "⏳ Waiting 10 seconds to observe network activity..." | tee -a "$log_file"
    sleep 10

    # Capture new network state
    new_netstat=$(netstat -an | grep ESTABLISHED | sort)
    new_connections=$(comm -13 <(echo "$baseline_netstat") <(echo "$new_netstat"))

    if [[ -n "$new_connections" ]]; then
      echo "🔍 New network connections:" | tee -a "$log_file"
      echo "$new_connections" | tee -a "$log_file"
      echo | tee -a "$log_file"

      echo "🔎 Resolving responsible processes:" | tee -a "$log_file"

      # Extract destination IPs and resolve reverse DNS
      echo "$new_connections" | awk '{print $5}' | cut -d. -f1-4 | sort | uniq | while read ip; do
        hostname=$(dig +short -x "$ip" | sed 's/\.$//')
        if [[ -z "$hostname" ]]; then hostname="(no reverse DNS)"; fi
        echo "➡️  $ip [$hostname]" | tee -a "$log_file"

        # Identify process responsible for connection to that IP
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

    # Update baseline
    baseline_netstat=$new_netstat
    echo "📡 Audit continues..." | tee -a "$log_file"
  fi

  sleep 1
done
