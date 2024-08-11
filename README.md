# CodeAlpha_NetworkPacketSniffer_Raghav
This repository contains a basic network packet sniffer structured using Python and implemented on Linux Kali. It is a project assigned through CodeAlpha's cyber security Internship.
This Python program is a basic network sniffer. A network sniffer captures and analyzes network traffic, allowing you to see the data being transmitted across a network. This can be useful for various purposes, including network troubleshooting, monitoring network activity, and understanding network protocols. Here's a detailed explanation of its use:

Key Uses of the Network Sniffer Program
Network Traffic Monitoring:

The program captures all data packets that pass through your network interface, allowing you to monitor the traffic in real-time. This can help in understanding how much data is being sent and received by different devices on the network.
Network Troubleshooting:

If there are issues with network performance or connectivity, a network sniffer can help identify the root cause by analyzing the types of packets being transmitted, their source and destination, and their protocols.
Security Analysis:

This program can be used to inspect suspicious activity on the network. For example, you can detect unauthorized connections, unusual data transfer patterns, or malformed packets that might indicate an attack.
Learning and Understanding Network Protocols:

For educational purposes, this program provides a hands-on way to learn about network protocols like Ethernet, IPv4, TCP, UDP, and ICMP. By examining the structure of the packets, you can gain a deeper understanding of how data is formatted and transmitted across networks.
Debugging and Testing Network Applications:

If you are developing network-based applications, this tool can help you debug and test your application by showing you the actual packets being sent and received by your application.
How the Program Works
Raw Socket Creation:

The program creates a raw socket that listens to all network traffic on a specific network interface. Raw sockets give access to the underlying network packet data without any filtering or abstraction.
Packet Capture:

The program continuously captures packets from the network interface using the recvfrom method. The packets are captured in their raw binary form.
Packet Parsing:

The captured packets are parsed to extract information such as MAC addresses, IP addresses, protocol types, and port numbers. This parsing helps in understanding the structure and contents of each packet.
The program identifies and processes different types of packets:
Ethernet Frame: The lowest layer, containing MAC addresses and the protocol type.
IPv4 Packet: The layer above Ethernet, containing IP addresses, TTL, and the protocol type (ICMP, TCP, UDP).
ICMP Packet: Typically used for network diagnostics (e.g., ping).
TCP Segment: A connection-oriented protocol used for reliable data transmission (e.g., HTTP, FTP).
UDP Segment: A connectionless protocol used for faster, but less reliable data transmission (e.g., DNS, VoIP).
Real-Time Output:

The program prints the parsed information to the terminal in real-time, providing a live view of the network activity.
