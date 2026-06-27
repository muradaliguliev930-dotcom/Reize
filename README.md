# REIZE (v3.1.0)

REIZE is an interactive, high-performance Cyberstalker OSINT & Network Scan Framework built in Python for penetration testing, host discovery, and intelligence gathering.

## 🚀 Key Features
- **Interactive CLI Shell**: Boots directly into a dedicated Metasploit-style console environment (`reize > `) with a custom command parser.
- **Raw Socket OSINT Engine**: Performs live network reconnaissance (`myip` and `site <domain>`) using low-level TCP/IP sockets to bypass proxies and virtual environments.
- **Multithreaded Network Scanner**: Rapidly discovers active hosts across subnets using Python's `threading` and concurrent queuing.
- **Graceful Error Handling**: Complete crash protection, ensuring clean exits on `Ctrl+C` without tracebacks.
- **Native Package Support**: Fully compatible with Debian/Kali Linux packagers for conversion into a native `.deb` system package.

## 🛠️ Global Subcommands inside CLI
- `help` - Show framework manual and active modules.
- `myip` - Run an OSINT check on your local and external network interface.
- `site <domain>` - Gather live intelligence on any target website (DNS resolution, geo-location, hosting provider, and WAF firewall analysis).
- `scan <subnet>` - Launch a fast multi-threaded port scan across a subnet range.
- `banner` - Clear the terminal and output the signature red cyberpunk ASCII logo.
- `exit` - Close the active shell session and safely terminate background threads.

## 📦 Local Installation
```bash
git clone https://github.com/muradaliguliev930-dotcom/Reize.git
cd Reize
python3 net_scanner.py
```

## 📜 License
MIT License

