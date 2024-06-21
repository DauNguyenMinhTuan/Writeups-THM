# Nmap

## Descriptions

An in depth look at scanning with Nmap, a powerful network scanning tool.
* Category: Walkthrough

### Introduction

When it comes to hacking, knowledge is power. The more knowledge you have about a target system or network, the more options you have available. This makes it imperative that proper enumeration is carried out before any exploitation attempts are made.

The first step of performing a security audit is to establish what services are running on the target system. This is called port scanning. Ports are networking constructs that are opened to receive connections. Ports are necessary for making multiple network requests or having multiple services available. Every computer has 65535 ports and many of them are registered as standard ports. However, theses ports can be altered, making it more imperative that we perform appropriate enumeration on the target.

It is crucial to start any attack with a port scan. This can be accomplished using **Nmap**. Nmap can be used to perform many different types of scans. However, the basic theory is that nmap will connect to each port of the target in turn. Depending on the response, nmap will determine if the port is open, closed, or filtered (usually by a firewall). Once we know which ports are open, we can then enumerate the services running on those ports.

There are also many other tools that can be used for port scanning. However, Nmap is the still the most popular and widely used as no other tool can match its functionality.

### Scan Types

There are many different types of scans that can be performed with Nmap. The 3 most common scans are:
* TCP Connect Scan `-sT`
* SYN "Half-Open" Scan `-sS`
* UDP Scan `-sU`

There are also some less common port scan types:
* TCP Null Scan `-sN`
* TCP FIN Scan `-sF`
* TCP Xmas Scan `-sX`

Most of these (except for the UDP scan) are used for very similar purposes, however, the way they work differs between each scan.

#### TCP Connect Scan

TCP Connect Scan works by performing the three-way handshake with each target port in turn.

If Nmap sends a TCP request with SYN flag set to a *closed* port, the target will respond with a RST packet. If the port is *open*, the target will respond with a SYN-ACK packet. If the port is *filtered*, the target will not respond at all.

However, it is easy to configure firewalls to respond with a RST packet. This can be extremely difficult (if not impossible) to get an accurate reading of the target.

#### SYN Scan

SYN Scan works slightly different to the TCP Connect Scan. Instead of performing the full three-way handshake, the SYN Scan sends back a RST packet after receiving the SYN-ACK packet from the target. This means that the target will not establish a full connection.

Some advantages of SYN Scan:
* SYN Scan are often not logged by listening applications as standard practice is to log a connection it's been fully established. This is why SYN Scan is often referred to as a "stealth" scan.
* Without having to establish a full connection, SYN Scan is much faster than TCP Connect Scan.

#### UDP Scan

UDP Scan relies on sending packets to target ports and essentially hoping that they make it. When a packet is sent and a UDP response is received (which is very unusual), the port is marked as *open*. More commonly, there is no response, in which case the packet is sent a second time to double check. If there is still no response, the port is marked as *open|filtered* and Nmap will move on. If the target responds with an ICMP port unreachable message, the port is marked as *closed*.

Due to the difficulty in identifying open ports, UDP Scan is much slower than TCP scans.

When scanning UDP ports, Nmap usually sends empty UDP packets to the target. That said, for ports which are usually occupied by well-known services, it will instead send a protocol-specific payload which is more likely to elicit a response from which a more accurate result can be drawn.

#### Null, FIN, and Xmas

These 3 scans are somewhat even stealthier than the SYN Scan. They work by sending packets with the TCP flags set to 0 (Null Scan), FIN (FIN Scan), and FIN, PSH, and URG (Xmas Scan). These scans are used to bypass firewalls that are configured to block SYN packets.

The expected responses is very similar to the UDP Scan. If there is no response, the port is marked as *open|filtered*. If the target responds with an RST packet, the port is marked as *closed*. If an ICMP unreachable message is received, the port is marked as *filtered*.

Although this behavior is mandated by RFC 793, many systems do not adhere to this standard. In particular Microsoft Windows (and a lot of Cisco network devices) are known to respond with a RST to any malformed TCP packet - regardless of whether the port is actually open or not. This results in all ports showing up as being closed.

That said, the goal of these scans is to bypass firewalls that are configured to block SYN packets.

### NSE Scripts

The Nmap Scripting Engine (NSE) is an incredibly powerful addition to Nmap, extending its functionality quite considerably. NSE Scripts are written in the Lua programming language, and can be used to do a variety of things: from scanning for vulnerabilities, to automating exploits for them. The NSE is particularly useful for reconnaisance, however, it is well worth bearing in mind how extensive the script library is.

There are many categories of NSE scripts, including:
* `safe`: won't affect the target
* `intrusive`: not safe, likely to affect the target
* `vuln`: scans for vulnerabilities
* `exploit`: attempts to exploit vulnerabilities
* `auth`: attempts to bypass authentication
* `brute`: attempts to brute force credentials
* `discovery`: scans for services

Scripts can be looked up at the [Nmap Scripting Engine Database](https://nmap.org/nsedoc/). It can also be looked up locally at `/usr/share/nmap/scripts/` with `ls` or `grep` on the database.