# NetMapper
Practical Experiments in Network Protocols and Attacks (Similar to Nmap)

## Overview

NetMapper was created as an internship project to:

- Discover active hosts on a network  
- Scan open ports and identify running services  
- Demonstrate network-based attacks in a lab environment for learning purposes

Implemented attack-simulations:

- TCP SYN Flooding  
- Brute-force password cracking 
- ARP spoofing  
- SMURF attack simulation  


## Features

- Host discovery (ARP, ICMP, TCP probing)  
- Port scanning (TCP connect, SYN, UDP probes)  
- Passive information gathering of services and processes  
- Lab-only attack simulations  



## Ethical Use

- Only run scans or attacks on networks you own or have explicit permission to test.  
- Use isolated virtual labs (Metasploitable2 or similar).  
- Unauthorized scanning or attacks are illegal and may result in penalties.  



## Requirements

**Software**

- macOS or Linux  
- C/C++ compiler (clang/gcc)  
- POSIX networking headers (`<sys/socket.h>`, `<arpa/inet.h>`, `<netinet/*>`)  
- Optional: root privileges for raw sockets  

**Hardware**

- NIC for sending/receiving packets  
- Sufficient RAM and disk space  


## Implementation

### Network Scanner - Identifying active hosts and open ports in a network
This passive attacker code performs network reconnaissance by utilising ICMP Echo Requests to identify active hosts within a specified CIDR-notated network range. 
Upon detecting an active host, the program employs TCP connections to scan for open ports on that host, spanning port numbers from 1 to 65535. 
- `NetworkScanner.cpp` implements this by systematically ensuring that each active host is only recorded and scanned once, thus avoiding redundant results.



###  TCP SYN Flooding Attack
In a TCP SYN flood attack, an attacker sends a large number of SYN (synchronisation) packets with spoofed source IP addresses to a target system's open ports. 
The objective of this attack is to overwhelm the target system's resources, particularly its ability to allocate resources for establishing and maintaining TCP connections.
- `TcpSynFloodingAttack.cpp` simulates this attack by targeting port 80 (HTTP) whose goal is to exhaust the target system's resources by overwhelming its ability to respond to the incoming SYN packets. 

### Brute Force Password Cracking Attack
 In a Brute Force attack, an attack gains unauthorized access to a system or service by systematically trying all possible combinations of passwords until the correct one is found.
 - `BruteForceAttack.cpp` attempts various authentication brute-force attacks on the target IP
 address while disabling host discovery.

### ARP Spoofing
ARP spoofing, also known as ARP poisoning, is a malicious technique used in computer networking to intercept, modify, or manipulate network traffic between two parties by sending fake Address Resolution Protocol (ARP) messages. ARP is used to map IP addresses to MAC addresses in a local network. In an ARP spoofing attack, an attacker sends forged ARP responses to associate their MAC address with the IP address of another host on the network, such as a default gateway. This causes traffic intended for the target host to be redirected to the attacker's machine.
- `ArpSpoofingAttack.cpp` simulates ARP spoofing by constructing an Ethernet header, IP header, and ICMP header to send an ICMP Echo Request (ping) packet.

### Smurf Attack
In a Smurf attack, a fake source address sends many ICMP packets to the broadcast address. 
The devices on the network react by replying back, which is what they're supposed to do for broadcast addresses. 
This ends up overwhelming the local network, causing a situation where it can't function properly.
- `SmurfAttack.cpp` simulates this attack by creating a simple UDP flood using raw sockets in C.
