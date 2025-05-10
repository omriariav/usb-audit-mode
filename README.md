# 🛡️ USB Audit Mode – A USB Watchdog Toolkit for macOS

> Ever plugged in a cheap keyboard from Temu and thought: *“Is this spying on me?”*  
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

## 📂 What’s Included

| Script                  | Description |
|-------------------------|-------------|
| `usb_audit.sh`          | Basic audit: monitors USB + network activity |
| `usb_audit_advanced.sh` | Advanced mode: includes behavioral security checks |

---

## 🧰 How to Use

```bash
chmod +x usb_audit.sh usb_audit_advanced.sh

./usb_audit.sh                # basic USB & network audit
./usb_audit_advanced.sh       # advanced mode defaults OFF
./usb_audit_advanced.sh --advanced  # paranoid mode: full behavioral checks
```

Logs are saved to:
```
usb_audit_log_YYYYMMDD_HHMMSS.txt
```

---

## 🚨 Advanced Mode Checks

When running `usb_audit_advanced.sh --advanced`, the script also:

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

## 🕵️ Red Flags to Watch For

- Devices drawing **>500mA** consistently
- No vendor/product ID
- Connections to unknown IPs with no matching process
- Shell commands using `curl`, `osascript`, or `sudo` right after USB plug-in
- Modified LaunchAgents in `~/Library/`

---

## 👤 Credits

Created by [@omriariav](https://x.com/omriariav) with help from ChatGPT.  
A script born of smart prompts, technical curiosity, and blunt criticism from imaginary Twitter haters.

---

## 📜 License

**Unlicense** — this project belongs to everyone.  
Use it, fork it, remix it. No attribution required.
