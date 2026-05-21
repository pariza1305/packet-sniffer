#  C-Shark — The Command-Line Packet Predator

A lightweight, multi-layer **network packet sniffer** written in C, built on top of [libpcap](https://www.tcpdump.org/). C-Shark lets you capture and dissect live network traffic right from your terminal, with detailed breakdowns across Layers 2 through 7 of the OSI model.

---

## Features

- **Device Discovery** — Automatically scans and lists all available network interfaces.
- **Live Packet Capture** — Sniffs real-time traffic on any selected interface using `libpcap`.
- **Deep Packet Dissection (L2–L7)**:
  - **L2 (Ethernet)** — Source/destination MAC addresses and EtherType.
  - **L3 (Network)** — Full support for IPv4, IPv6, and ARP (IP addresses, TTL, protocol type, flow labels).
  - **L4 (Transport)** — TCP (sequence/ack numbers, flags, window size) and UDP (length, checksum).
  - **L7 (Application)** — Protocol identification (HTTP, HTTPS/TLS, DNS) and hex+ASCII payload dump.
- **BPF Protocol Filtering** — Apply Berkeley Packet Filters to narrow capture to `TCP`, `UDP`, `ARP`, `DNS`, `HTTP`, or `HTTPS`.
- **Session Storage** — Automatically saves the most recent capture session in memory (up to 1000 packets).
- **In-Depth Inspection** — Select any packet from the last session for a verbose, field-by-field breakdown with a full hex dump.
- **Graceful Controls** — `Ctrl+C` stops the live capture without exiting; `Ctrl+D` exits cleanly.

---

## Project Structure

```
packet-sniffer/
├── include/
│   ├── dissector.h     # Packet dissection interface
│   ├── sniffer.h       # Capture session interface
│   ├── storage.h       # Packet storage interface
│   └── utils.h         # Utility functions (hex dump, MAC printing, TCP flags)
├── src/
│   ├── main.c          # Entry point, menus, and program loop
│   ├── sniffer.c       # libpcap capture loop and BPF filter setup
│   ├── dissector.c     # Layer-by-layer packet dissection (L2–L7)
│   ├── storage.c       # Session memory management and inspection
│   └── utils.c         # Helper functions (hex/ASCII dump, port→service map)
└── Makefile
```

---

## Prerequisites

You will need:

- **GCC** (or any C99-compatible compiler)
- **libpcap** development library

### Installing libpcap

**macOS:**
```bash
brew install libpcap
```

**Debian / Ubuntu:**
```bash
sudo apt-get install libpcap-dev
```

**Fedora / RHEL:**
```bash
sudo dnf install libpcap-devel
```

---

## Building

Clone the repository and build with `make`:

```bash
git clone https://github.com/your-username/packet-sniffer.git
cd packet-sniffer/packet-sniffer
make
```

This compiles all source files and produces the `cshark` executable in the project root.

To clean up build artifacts:

```bash
make clean
```

---

## Usage

Packet capture requires **root/administrator privileges** to access raw network interfaces.

```bash
sudo ./cshark
```

### Walkthrough

1. **Select an interface** — C-Shark lists all available network interfaces and prompts you to pick one.

2. **Choose an action** from the main menu:
   ```
   1. Start Sniffing (All Packets)
   2. Start Sniffing (With Filters)
   3. Inspect Last Session
   4. Exit C-Shark
   ```

3. **If using filters**, select a protocol:
   ```
   1. HTTP  (port 80)
   2. HTTPS (port 443)
   3. DNS   (port 53)
   4. ARP
   5. TCP
   6. UDP
   ```

4. **Press `Ctrl+C`** to stop the live capture and return to the main menu.

5. **Inspect Last Session** — View a summary of all captured packets and enter a Packet ID for a detailed, layer-by-layer breakdown including a full hex dump.

---

## Example Output

```
[C-Shark] The Command-Line Packet Predator
==============================================
[C-Shark] Searching for available interfaces... Found!

1. en0
2. lo0

Select an interface to sniff (1-2): 1

[C-Shark] Interface 'en0' selected. What's next?

1. Start Sniffing (All Packets)
...

-----------------------------------------
Packet #1 | Timestamp: 1716278412.034521 | Length: 74 bytes
L2 (Ethernet): Dst MAC: FF:FF:FF:FF:FF:FF | Src MAC: A4:C3:F0:12:34:56 |
EtherType: IPv4 (0x0800)
L3 (IPv4): Src IP: 192.168.1.10 | Dst IP: 8.8.8.8 | Protocol: TCP (6) | TTL: 64
L4 (TCP): Src Port: 54321 (Other) | Dst Port: 443 (HTTPS) | Seq: 123456 | Ack: 0 | Flags: [SYN]
```

---

## Technical Details

| Component     | Technology                              |
|---------------|-----------------------------------------|
| Language      | C (C99)                                 |
| Capture Engine| libpcap                                 |
| Filtering     | Berkeley Packet Filter (BPF) expressions|
| Protocols     | Ethernet, IPv4, IPv6, ARP, TCP, UDP     |
| App Protocols | HTTP, HTTPS/TLS, DNS                    |
| Build System  | GNU Make                                |
| Platform      | Linux / macOS                           |

---

## Limitations

- Session storage is capped at **1000 packets** per capture.
- The session inspector currently assumes **Ethernet-encapsulated** packets (i.e., does not support loopback or other link-layer types in the summary view).
- L7 protocol identification is **port-based** (no deep payload inspection).
- Windows is not supported; requires POSIX-compatible sockets and headers.

---

## License

This project is open-source and available under the [MIT License](LICENSE).