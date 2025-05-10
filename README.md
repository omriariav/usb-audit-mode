# 🛡️ USB Audit Mode – A USB Watchdog Toolkit for macOS

> Ever plugged in a cheap keyboard and thought: *"Is this spying on me?"*  
> This toolkit answers that — from chill mode to full paranoia.

---

## 🧠 What is this?

A macOS shell script toolkit to monitor USB plug-ins and detect suspicious behavior, including:

- USB device info (vendor, product, power draw)
- New outbound network connections after plug-in
- Reverse DNS lookup for each connection
- The local process responsible for each connection (if any)
- (**Advanced mode**) Behavioral checks for rubber ducky-style attacks or host-level persistence

---

## 📂 What's Included

| Script                  | Description |
|-------------------------|-------------|
| `usb_audit.py`          | Unified Python script for USB and network auditing with optional advanced checks |
| `usb_audit.sh`          | Basic audit: monitors USB + network activity (legacy) |
| `usb_audit_advanced.sh` | Advanced mode: includes behavioral security checks (legacy) |

---

## 🧰 How to Use

```bash
python3 usb_audit.py                # Run the audit with default settings
python3 usb_audit.py --advanced     # Enable advanced checks
python3 usb_audit.py --verbose      # Enable verbose output for detailed logs
```

Logs are saved to:
```
usb_audit_log_YYYYMMDD_HHMMSS.txt
```

By default, the script displays comments and status messages on the screen. Use the `--verbose` flag to see detailed command outputs and logs.

---

## 🚨 Advanced Mode Checks

When running `python3 usb_audit.py --advanced`, the script also:

- Detects `Terminal` launched after USB plug-in
- Checks recent shell commands (`curl`, `wget`, `osascript`, `sudo`)
- Lists login items and recently modified LaunchAgents
- Flags devices acting as HID + storage or with suspicious power draw

---

## 🔍 Sample Output (Basic)

```
⚠️  USB device connected: 2025-05-10 14:27:03
🧪 USB Device Snapshot (ioreg):
  "USB Product Name" = "Snpurdiri 60%"
  "USB Vendor Name" = "Unknown"
  "Current Required" = 500

🔍 New network connections:
  tcp4 10.0.0.1:51254 → 54.158.153.99:443 ESTABLISHED

➡️  54.158.153.99 [ec2-54-158-153-99.compute-1.amazonaws.com]
  COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
  Slack    2104 omri    37u  IPv4  ...   TCP ...
```

---

## 🚨 Red Flags to Watch For

- Devices drawing **>500mA** consistently
- No vendor/product ID
- Connections to unknown IPs with no matching process
- Shell commands using `curl`, `osascript`, or `sudo` right after USB plug-in
- Modified LaunchAgents in `~/Library/`

These red flags are now displayed directly on the screen during the audit process, providing immediate feedback to the user.

---

## 👤 Credits

Created by [@omriariav](https://x.com/omriariav) with help from ChatGPT.  
A script born of smart prompts, technical curiosity, and blunt criticism from imaginary Twitter haters.

---

## 📜 License

**Unlicense** — this project belongs to everyone.  
Use it, fork it, remix it. No attribution required.
