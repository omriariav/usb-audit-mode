# 🛡️ usb-audit-mode.sh – A USB Watchdog for macOS

> Ever bought a $9 keyboard from Temu and wondered, *“Is this thing spying on me?”*  
> This script helps you find out.

## 🧠 What is this?

`usb-audit-mode.sh` is a lightweight macOS shell script that watches for USB device plug-ins and logs:

- USB device info (vendor, product, power draw)
- New outbound network connections after the device is plugged in
- Reverse DNS lookup for each connection
- The local process responsible for each connection (if any)

## 🚀 Features

- ✅ No installations or brew dependencies
- ✅ Uses only macOS built-in tools (`log`, `ioreg`, `netstat`, `lsof`, `dig`)
- ✅ Runs from the terminal with `Ctrl+C` to stop
- ✅ Saves logs to a timestamped file
- ✅ Great for paranoid power users, tinkerers, and security-conscious devs

## 💡 Example Use Case

You're testing a new USB device (keyboard, hub, charger, badge reader...) and want to make sure:

- It doesn't spawn hidden background processes
- It doesn't initiate suspicious outbound connections
- It isn’t drawing unusually high current (⚠️ hello hardware keylogger)

## 🧰 How to Use

```bash
git clone https://github.com/YOUR_USERNAME/usb-audit-mode.git
cd usb-audit-mode
chmod +x usb_audit.sh
./usb_audit.sh
```

The script will watch for USB device connections and log:

- System USB event entries
- Power draw, vendor/product IDs
- Network changes 10 seconds after plug-in
- Destination IPs + responsible processes

Logs will be saved to:
```
usb_audit_log_YYYYMMDD_HHMMSS.txt
```

## 📎 Sample Output

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

## 🕵️‍♂️ Red Flags to Watch For

- Devices drawing **>500mA** consistently (especially HID-class keyboards)
- No vendor/product ID shown in `ioreg`
- Connections to unknown IPs with no process attached
- Background traffic to data centers shortly after plug-in

## 👤 Credits

Created by [@omriariav](https://x.com/omriariav), who asked smart, privacy-driven questions and used ChatGPT to collaborate on this tool.

Special thanks to ChatGPT (hi, that's me 👋) for Bash scripting, reverse DNS lookups, and keeping things ✨ paranoid but practical ✨.

## 📜 License

Unlicense. Use, fork, remix freely. No attribution required.
