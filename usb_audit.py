import argparse
import datetime
import time
import subprocess

# Function to get current network connections
def get_network_connections():
    result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
    return set(result.stdout.splitlines())

# Function to log messages
def log_message(message, log_file, verbose=False, always_print=False):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}"
    if verbose or always_print:
        print(log_entry)
    with open(log_file, "a") as f:
        f.write(log_entry + "\n")

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

    # Check for suspicious shell history
    log_message("🧠 Suspicious shell history (curl/wget/sudo):", log_file)
    log_message("🔍 Checking for suspicious shell history...", log_file)
    shell_history_result = subprocess.run(['grep', '-E', 'curl|wget|osascript|sudo', '~/.zsh_history'], capture_output=True, text=True, shell=True)
    log_message(shell_history_result.stdout, log_file)
    if shell_history_result.stdout:
        suspicious_commands = shell_history_result.stdout.strip()
        log_message(f"🚩 Red Flag: Suspicious shell command executed after USB plug-in! Commands: {suspicious_commands}. This could indicate an attempt to download or execute malicious scripts. Review recent command history and ensure no unauthorized scripts are running.", log_file)

    # Add any other advanced checks here

    log_message("🛡️ Advanced checks completed.", log_file)

# Main function
def main():
    parser = argparse.ArgumentParser(description='USB Audit Mode')
    parser.add_argument('--advanced', action='store_true', help='Enable advanced checks')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"usb_audit_log_{timestamp}.txt"
    alert_log_file = f"usb_audit_alerts_{timestamp}.txt"
    alerts = set()

    log_message("🔌 USB Audit Mode Started", log_file, args.verbose, always_print=True)
    log_message("🔍 Monitoring for USB plug-ins, network activity, and suspicious behaviors...", log_file, args.verbose, always_print=True)

    baseline_netstat = get_network_connections()

    while True:
        usb_event = detect_usb_event()
        if usb_event:
            log_message("⚠️  USB device connected", log_file, args.verbose, always_print=True)
            log_message("🔍 USB event detected, logging details...", log_file, args.verbose, always_print=True)
            if args.verbose:
                log_message(usb_event, log_file, args.verbose)

            usb_info = get_usb_device_info()
            log_message("🧪 USB Device Snapshot (ioreg):", log_file, args.verbose, always_print=True)
            log_message("🔍 Gathering USB device information...", log_file, args.verbose, always_print=True)
            if args.verbose:
                log_message(usb_info, log_file, args.verbose)

            # Check for red flags in USB device information
            for line in usb_info.splitlines():
                if "Current" in line and any(x in line for x in ["500", "600", "700", "800", "900", "1000"]):
                    device_info = line.split('=')[-1].strip()
                    alert = f"🚩 Red Flag: Device drawing more than 500mA! Device: {device_info}. This could indicate a device that is using more power than typical USB peripherals, potentially pointing to malicious hardware. Consider checking the device's specifications or replacing it if unexpected."
                    log_message(alert, log_file, args.verbose, always_print=True)
                    alerts.add(alert)
                if "Vendor" in line and "Unknown" in line:
                    device_info = line.split('=')[-1].strip()
                    alert = f"🚩 Red Flag: Device with no vendor ID! Device: {device_info}. Devices without a known vendor ID might be counterfeit or malicious. Verify the device's legitimacy or avoid using it if suspicious."
                    log_message(alert, log_file, args.verbose, always_print=True)
                    alerts.add(alert)
                if "Product" in line and "Unknown" in line:
                    device_info = line.split('=')[-1].strip()
                    alert = f"🚩 Red Flag: Device with no product ID! Device: {device_info}. Devices without a known product ID might be counterfeit or malicious. Verify the device's legitimacy or avoid using it if suspicious."
                    log_message(alert, log_file, args.verbose, always_print=True)
                    alerts.add(alert)

            log_message("⏳ Waiting 10 seconds to observe network activity...", log_file, args.verbose, always_print=True)
            time.sleep(10)

            new_netstat = get_network_connections()
            new_connections = new_netstat - baseline_netstat

            if new_connections:
                log_message("🔍 New network connections detected:", log_file, args.verbose, always_print=True)
                for connection in new_connections:
                    log_message(connection, log_file, args.verbose)

                log_message("🔎 Resolving responsible processes for new connections:", log_file, args.verbose, always_print=True)
                for connection in new_connections:
                    ip = connection.split()[4].split('.')[0:4]
                    ip = '.'.join(ip)
                    hostname_result = subprocess.run(['dig', '+short', '-x', ip], capture_output=True, text=True)
                    hostname = hostname_result.stdout.strip() or "(no reverse DNS)"
                    log_message(f"➡️  {ip} [{hostname}]", log_file, args.verbose)

                    lsof_result = subprocess.run(['lsof', '-nP', '-i', f'@{ip}'], capture_output=True, text=True)
                    if lsof_result.stdout:
                        log_message(lsof_result.stdout, log_file, args.verbose)
                    else:
                        alert = f"🚩 Red Flag: Connection to unknown IP {ip} with no matching process! This could indicate unauthorized data exfiltration or communication with a malicious server. Consider monitoring network traffic or blocking the IP if unrecognized."
                        log_message(alert, log_file, args.verbose, always_print=True)
                        alerts.add(alert)
            else:
                log_message("✅ No new network connections detected.", log_file, args.verbose, always_print=True)

            baseline_netstat = new_netstat

            if args.advanced:
                perform_advanced_checks(log_file)

            log_message("📡 Audit continues...", log_file, args.verbose, always_print=True)

            # Write unique alerts to a separate file
            with open(alert_log_file, "w") as alert_file:
                for alert in alerts:
                    alert_file.write(alert + "\n")

        time.sleep(1)

if __name__ == "__main__":
    main() 