# computer-security

Two security tools developed for CSE331 - Computer Security Fundamentals at Stony Brook University.
Written in Python using Scapy for packet analysis/manipulation on Linux systems.

1. arpwatch.py is a simple ARP poisoning detector. On startup, it reads the system's current ARP table, then monitors the ARP traffic and prints a warning whenever a MA=IP binding is changed.

2. synprobe.py is a TCP service fingerprinting tool. It performs a simple TCP SYN scan on one or more ports, attempts to connect to any open ports, sends it a "dummy packet" and prints the response (if any).
