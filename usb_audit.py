import subprocess
import time
import datetime
import sys

# Function to log messages
def log_message(message, log_file):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}"
    print(log_entry)
    with open(log_file, "a") as f:
        f.write(log_entry + "\n")

# Function to get current network connections
def get_network_connections():
    result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
    return set(result.stdout.splitlines())

# Function to detect USB events
def detect_usb_event():
    result = subprocess.run(['log', 'show', '--style', 'syslog', '--predicate', 'eventMessage CONTAINS "USB"', '--last', '1s'], capture_output=True, text=True)
    return result.stdout

# Function to get USB device information
def get_usb_device_info():
    result = subprocess.run(['ioreg', '-p', 'IOUSB', '-l'], capture_output=True, text=True)
    return result.stdout

# Function to perform advanced checks
def perform_advanced_checks(log_file):
    log_message("🛡️ Running advanced checks...", log_file)

    # Check for recently modified LaunchAgents
    log_message("📁 Recently modified LaunchAgents:", log_file)
    log_message("🔍 Checking for recently modified LaunchAgents...", log_file)
    find_result = subprocess.run(['find', '~/Library/LaunchAgents', '-type', 'f', '-mmin', '-5'], capture_output=True, text=True, shell=True)
    log_message(find_result.stdout, log_file)

    # Check for recent Terminal activity
    log_message("🧯 Recent Terminal activity (log):", log_file)
    log_message("🔍 Checking for recent Terminal activity...", log_file)
    terminal_log_result = subprocess.run(['log', 'show', '--predicate', 'processImagePath CONTAINS "Terminal"', '--last', '30s'], capture_output=True, text=True)
    log_message(terminal_log_result.stdout, log_file)

    # List recent login items
    log_message("📝 Recent login items:", log_file)
    log_message("🔍 Listing recent login items...", log_file)
    login_items_result = subprocess.run(['osascript', '-e', 'tell application "System Events" to get the name of every login item'], capture_output=True, text=True)
    log_message(login_items_result.stdout, log_file)

    # Check for suspicious shell history
    log_message("🧠 Suspicious shell history (curl/wget/sudo):", log_file)
    log_message("🔍 Checking for suspicious shell history...", log_file)
    shell_history_result = subprocess.run(['grep', '-E', 'curl|wget|osascript|sudo', '~/.zsh_history'], capture_output=True, text=True, shell=True)
    log_message(shell_history_result.stdout, log_file)
    if shell_history_result.stdout:
        log_message("🚩 Red Flag: Suspicious shell command executed after USB plug-in!", log_file)

# Main function
def main():
    advanced_mode = "--advanced" in sys.argv

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"usb_audit_log_{timestamp}.txt"
    log_message("🔌 USB Audit Mode Started", log_file)
    log_message("🔍 Monitoring for USB plug-ins, network activity, and suspicious behaviors...", log_file)

    baseline_netstat = get_network_connections()

    while True:
        usb_event = detect_usb_event()
        if usb_event:
            log_message("⚠️  USB device connected", log_file)
            log_message("🔍 USB event detected, logging details...", log_file)
            log_message(usb_event, log_file)

            usb_info = get_usb_device_info()
            log_message("🧪 USB Device Snapshot (ioreg):", log_file)
            log_message("🔍 Gathering USB device information...", log_file)
            log_message(usb_info, log_file)

            # Check for red flags in USB device information
            for line in usb_info.splitlines():
                if "Current" in line and any(x in line for x in ["500", "600", "700", "800", "900", "1000"]):
                    log_message("🚩 Red Flag: Device drawing more than 500mA!", log_file)
                if "Vendor" in line and "Unknown" in line:
                    log_message("🚩 Red Flag: Device with no vendor ID!", log_file)
                if "Product" in line and "Unknown" in line:
                    log_message("🚩 Red Flag: Device with no product ID!", log_file)

            log_message("⏳ Waiting 10 seconds to observe network activity...", log_file)
            time.sleep(10)

            new_netstat = get_network_connections()
            new_connections = new_netstat - baseline_netstat

            if new_connections:
                log_message("🔍 New network connections detected:", log_file)
                for connection in new_connections:
                    log_message(connection, log_file)

                log_message("🔎 Resolving responsible processes for new connections:", log_file)
                for connection in new_connections:
                    ip = connection.split()[4].split('.')[0:4]
                    ip = '.'.join(ip)
                    hostname_result = subprocess.run(['dig', '+short', '-x', ip], capture_output=True, text=True)
                    hostname = hostname_result.stdout.strip() or "(no reverse DNS)"
                    log_message(f"➡️  {ip} [{hostname}]", log_file)

                    lsof_result = subprocess.run(['lsof', '-nP', '-i', f'@{ip}'], capture_output=True, text=True)
                    if lsof_result.stdout:
                        log_message(lsof_result.stdout, log_file)
                    else:
                        log_message("⚠️  No process found (connection may have closed)", log_file)
                        log_message("🚩 Red Flag: Connection to unknown IP with no matching process!", log_file)
            else:
                log_message("✅ No new network connections detected.", log_file)

            baseline_netstat = new_netstat

            if advanced_mode:
                perform_advanced_checks(log_file)

            log_message("📡 Audit continues...", log_file)

        time.sleep(1)

if __name__ == "__main__":
    main() 