# What is the Use of this Tool? 
- Asset Inventory: Identifying every computer, smartphone, or IoT device currently 
connected to the network. 
- Security Auditing: Detecting "rogue devices" that shouldn't be on the network. 
- Troubleshooting: Verifying if a specific IP address is reachable and determining its 
likely operating system. 
- Network Mapping: Calculating the network range (CIDR) and identifying the default 
gateway. 

# How It Works 
The tool follows a four-step lifecycle: 

#### I. Interface Discovery 
The tool looks at your hardware (Ethernet or Wi-Fi cards). It ignores the "loopback" (127.0.0.1) 
and calculates the network range based on your IP address and Subnet Mask. 

#### II. Selection of Probing Method 
You are given three distinct ways to find hosts, each with different "visibility": 
- ICMP Ping: Sends a standard "Are you there?" packet. It guesses the OS (Windows vs. 
Linux) by looking at the TTL (Time to Live) value in the response. 
- ARP Scan: The most accurate for local networks. It asks the network "Who has this 
IP?" and records the hardware (MAC) address of whoever replies. 
- TCP Probe: Tries to connect to common ports (22, 80, 443). If a device doesn't respond 
to pings (common for Windows firewalls), it might still respond to a web port. 

#### III. Multi-Threaded Execution 
Instead of checking one IP at a time (which would be very slow), the tool uses a 
ThreadPoolExecutor to check up to 100 IPs simultaneously, making the scan finish in seconds 
rather than minutes. 

#### IV. Reporting 
Finally, it prints a table of live hosts, their MAC addresses (if found via ARP), and the guessed 
Operating System.
