**Device Discovery**: Automatically scans and lists all available network interfaces for capture.
* **Live Packet Capture**: Sniffs network traffic in real-time on a selected interface.
* **Detailed Dissection (Layers 2-7)**:
    * **L2 (Data Link)**: Parses Ethernet headers, showing source/destination MAC addresses and EtherType.
    * **L3 (Network)**: Decodes IPv4, IPv6, and ARP packets, displaying crucial information like IP addresses, TTL, and protocol types.
    * **L4 (Transport)**: Unpacks TCP and UDP segments, detailing ports, sequence/acknowledgment numbers, and flags.
    * **L7 (Payload)**: Identifies common application protocols (HTTP, HTTPS, DNS) based on port numbers and provides a hex dump of the payload data.
* **Protocol Filtering**: Narrows down the live capture to show only specific protocols like `TCP`, `UDP`, `ARP`, `DNS`, `HTTP`, or `HTTPS`.
* **Session Storage**: Automatically saves the most recent capture session in memory for later analysis.
* **In-Depth Inspection**: Allows a user to select a single packet from the last session and view a highly detailed, field-by-field breakdown of all its protocol layers.
* **Graceful Controls**: Use `Ctrl+C` to stop a live capture without terminating the program and `Ctrl+D` to exit cleanly.