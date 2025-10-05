# Cerberus Advanced Usage Guide

Cerberus is a powerful network packet crafting and flooding tool designed for network testing, security research, and penetration testing. It allows users to generate various types of network traffic to simulate attacks, test network resilience, and analyze protocol behaviors.

## Capabilities

Cerberus can:
- Craft and send custom packets at high speeds
- Perform various DoS/DDoS simulation attacks
- Spoof source IP addresses
- Target specific ports or port ranges
- Support both IPv4 and IPv6 protocols
- Generate fragmented packets
- Customize packet sizes and flags
- Run multiple attack types simultaneously

## Supported Protocols

### TCP (Transmission Control Protocol)
TCP is a connection-oriented protocol that provides reliable, ordered, and error-checked delivery of data between applications. Cerberus can manipulate TCP flags to simulate different connection states and behaviors.

### UDP (User Datagram Protocol)
UDP is a connectionless protocol that provides fast, unreliable data transmission. It's used for applications requiring speed over reliability, like DNS, VoIP, and streaming.

### ICMP (Internet Control Message Protocol)
ICMP is used for error reporting and diagnostic functions in IP networks. It sends control messages about network conditions, such as unreachable hosts or network congestion.

### ICMPv6
The IPv6 version of ICMP, used for similar diagnostic and error-reporting functions in IPv6 networks, including Neighbor Discovery and Router Advertisement.

## Basic Syntax

```
cerberus -4|-6 [options]
```

- `-4`: Use IPv4 protocol
- `-6`: Use IPv6 protocol

You must specify either `-4` or `-6`, but not both.

## Attack Types

### -U: UDP Attack
Performs a UDP flood attack by sending a high volume of UDP datagrams to overwhelm network bandwidth and processing resources.
```
cerberus -4 -U -h <target_ip> -t <timeout>
```
- No additional options required
- Sends random UDP packets to random or specified ports
- Effective for bandwidth exhaustion and UDP-based service disruption
- Can bypass some TCP-focused security measures

### -I: ICMP Attack
Performs an ICMP echo flood (ping flood) attack by sending massive amounts of ICMP Echo Request packets.
```
cerberus -4 -I -h <target_ip> -t <timeout>
```
- No additional options required
- Sends ICMP echo requests (ping packets) to the target
- Consumes bandwidth and requires the target to respond with echo replies
- Often filtered by modern firewalls but effective against unprotected hosts

### -R: Router Attack
Performs an ICMPv6 Router Advertisement flood attack (IPv6 only), designed to disrupt IPv6 network routing.
```
cerberus -6 -R -h <target_ip> -t <timeout>
```
- No additional options required
- Sends ICMPv6 Router Advertisement packets to announce fake routers
- Can cause routing table corruption and man-in-the-middle opportunities
- Exploits IPv6's automatic router discovery mechanisms

### -T: TCP Attack
Performs various TCP-based attacks by manipulating TCP control flags to simulate different network conditions and exhaust server resources.
```
cerberus -4 -T <type>[,<data_size>] -h <target_ip> -t <timeout>
```
- `<type>`: Attack type (0-9)
  - 0: FIN packets - Sends TCP FIN packets to attempt closing non-existent connections, potentially causing resource exhaustion
  - 1: SYN packets (SYN flood) - Initiates half-open TCP connections, exhausting server's connection queue and SYN backlog
  - 2: RST packets - Sends TCP reset packets, potentially disrupting legitimate connections
  - 3: PUSH packets - Forces immediate data delivery, can be used to flood with small packets
  - 4: ACK packets - Sends acknowledgment packets, useful for testing firewall rules and state tracking
  - 5: URG packets - Sets urgent pointer, can be used to test buffer handling
  - 6: ECE packets (Explicit Congestion Experienced) - Indicates network congestion, used in ECN (Explicit Congestion Notification)
  - 7: CWR packets (Congestion Window Reduced) - Signals congestion window reduction in ECN
  - 8: NOF (No Flags) packets - Sends TCP packets with no flags set, invalid but can test protocol handling
  - 9: FRAG (Fragmented) packets - Sends fragmented TCP packets, testing reassembly capabilities and potentially bypassing filters
- `<data_size>`: Optional data size after TCP header (default: 4 bytes, max: 4096)

Example:
```
cerberus -4 -T 1,100 -h 192.168.1.1 -t 60
```
Performs a SYN flood with 100 bytes of data per packet for 60 seconds, potentially overwhelming the target's TCP stack.

### -B: Bomb Attack
Performs connection-based bomb attacks that establish connections and send large payloads to exhaust memory and processing resources.
```
cerberus -4 -B <type>,<size> -h <target_ip> -t <timeout>
```
- `<type>`: Bomb type
  - 0: TCP bomb - Establishes TCP connections and sends large TCP payloads, exhausting server memory and connection resources
  - 1: UDP bomb - Sends large UDP datagrams, consuming bandwidth and potentially crashing UDP-based services
  - 2: RAW bomb - Sends raw IP packets with large payloads, bypassing protocol-specific handling for maximum impact
- `<size>`: Packet size (default: 64 bytes, max: 2048)
- Requires actual connection establishment (unlike stateless floods)
- More resource-intensive but potentially more effective against protected targets

Example:
```
cerberus -4 -B 0,512 -h 192.168.1.1 -t 30
```
Establishes TCP connections and sends 512-byte payloads for 30 seconds, potentially overwhelming the target's memory and CPU.

## Targeting Options

### -h: Destination IP
Specifies the target IP address.
```
-h <ip_address>
```
- Required for most attacks
- For IPv4: Use dotted decimal (e.g., 192.168.1.1)
- For IPv6: Use colon-separated (e.g., 2001:db8::1)

### -d: Destination Class
Specifies a destination IP class/range for random targeting.
```
-d <class>
```
- Examples:
  - `192.168.1.` (random IPs in 192.168.1.0/24)
  - `10.0.` (random IPs in 10.0.0.0/16)
  - `2001:db8::` (IPv6 range)

### -p: Destination Port Range
Specifies the destination port range.
```
-p <start>,<end>
```
- Default: Random ports
- Example: `-p 80,443` (ports 80 to 443)

### -q: Source Port Range
Specifies the source port range.
```
-q <start>,<end>
```
- Default: Random ports
- Example: `-q 1024,65535` (ephemeral ports)

## Source Options

### -s: Source Class/IP
Specifies the source IP class or specific IP.
```
-s <source>
```
- Default: Random source IPs
- Examples:
  - `192.168.1.100` (specific IP)
  - `10.0.` (random from 10.0.0.0/16)
  - `2001:db8::1` (IPv6 specific)

## Timing and Control

### -t: Timeout
Specifies the attack duration in seconds.
```
-t <seconds>
```
- Required
- Example: `-t 300` (5 minutes)

### -w: Window Size
Sets the TCP window size.
```
-w <size>
```
- Range: 1-65535
- Default: Random
- Only affects TCP-based attacks

## Help

### -H: Help
Displays the help message.
```
-H
```
- Shows all available options and their descriptions

## Complete Examples

### SYN Flood Attack
```
cerberus -4 -T 1 -h 192.168.1.1 -t 60 -s 10.0.0.1 -p 80,80
```
- IPv4 SYN flood on port 80 for 60 seconds
- Spoofed source IP: 10.0.0.1

### UDP Flood with Port Range
```
cerberus -4 -U -d 192.168.1. -t 120 -p 53,53 -q 53,53
```
- IPv4 UDP flood on random IPs in 192.168.1.0/24
- Target port: 53 (DNS)
- Source port: 53

### IPv6 ICMPv6 Router Advertisement
```
cerberus -6 -R -h 2001:db8::1 -t 30 -s 2001:db8:1::1
```
- IPv6 router advertisement flood
- Target: 2001:db8::1
- Source: 2001:db8:1::1

### Mixed TCP Attacks
```
cerberus -4 -T 0 -T 1 -T 4 -h 192.168.1.1 -t 90 -w 65535
```
- Combines FIN, SYN, and ACK attacks
- Window size: 65535

## Important Notes and Warnings

### Legal and Ethical Considerations
- **LEGAL WARNING**: Only use Cerberus on networks and systems you own or have explicit written permission to test. Unauthorized use may violate laws such as the Computer Fraud and Abuse Act (CFAA) in the US or equivalent laws in other countries.
- **ETHICAL USE**: This tool is designed for network testing, security research, and penetration testing with proper authorization. Misuse can cause significant harm, including service disruption, data loss, and legal consequences.

### Technical Requirements
- Most attacks require root/administrator privileges to send raw packets
- IPv6 attacks may require IPv6 connectivity and proper routing
- Packet rates depend on system performance, network speed, and hardware capabilities
- Some attacks may be mitigated by modern firewalls, IDS/IPS systems, or rate limiting

### Protocol-Specific Behavior
- **TCP Attacks**: Manipulate connection state machines, potentially exhausting connection tables
- **UDP Attacks**: Stateless floods that consume bandwidth without requiring responses
- **ICMP Attacks**: Require targets to generate responses, doubling network traffic
- **Bomb Attacks**: Establish actual connections, making them more detectable but potentially more damaging

### Best Practices
- Start with low-intensity tests and gradually increase
- Monitor both source and target systems for performance impact
- Use in controlled lab environments for initial testing
- Document all testing activities and obtain proper authorization
- Be aware that some attacks may trigger automated defense responses
