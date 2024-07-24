# Actice Reconnaissance

## Description

Learn how to use simple tools such as traceroute, ping, telnet, and a web browser to gather information.
* Category: Walkthrough

## Introduction

Active reconnaissance requires us to make some kind of contact with our target. This contact can be a phone call or a visit to the target company under some pretence to gather more information, usually as part of social engineering.

Alternatively, it can be a direct connection to the target system, whether visiting their website or checking if their firewall has an SSH port open. Think of it like we are closely inspecting windows and door locks. Hence, it is essential to remember not to engage in active reconnaissance work before getting signed legal authorization from the client.

Active reconnaissance begins with direct connections made to the target machine. Any such connection might leave information in the logs showing the client IP address, time of the connection, and duration of the connection, among other things.

However, not all connections are suspicious. It is possible to let our active reconnaissance appear as regular client activity. Consider web browsing. No one would suspect a browser connected to a target web server among hundreds of other legitimate users. We can use such techniques to our advantage when working as part of the red team (attackers) and don’t want to alarm the blue team (defenders).

## Web Browser

The web browser can be a convenient tool, especially that it is readily available on all systems. There are several ways where we can use a web browser to gather information about a target.

On the transport level, the browser connects to:
* TCP port 80 by default when the website is accessed over HTTP.
* TCP port 443 by default when the website is accessed over HTTPS.

Since 80 and 443 are default ports for HTTP and HTTPS, the web browser does not show them in the address bar. However, it is possible to use custom ports to access a service.

While browsing a web page, we can press `Ctrl+Shift+I` on a PC or `Option+Command+I` (`⌥+⌘+I`) on a Mac to open the Developer Tools on **Firefox**. Similar shortcuts will also get us started with **Google Chrome** or **Chromium**. Developer Tools lets us inspect many things that our browser has received and exchanged with the remote server.

There are also plenty of add-ons for Firefox and Chrome that can help in penetration testing. Here are a few examples:
* **FoxyProxy** lets us quickly change the proxy server we are using to access the target website. This browser extension is convenient when we are using a tool such as Burp Suite or if we need to switch proxy servers regularly.
* **User-Agent Switcher and Manager** gives us the ability to pretend to be accessing the webpage from a different operating system or different web browser. In other words, we can pretend to be browsing a site using an iPhone when in fact, we are accessing it from Mozilla Firefox.
* **Wappalyzer** provides insights about the technologies used on the visited websites. Such extension is handy, primarily when we collect all this information while browsing the website like any other user.

## Ping

Ping should remind us of the game ping-pong. We throw the ball and expect to get it back. The primary purpose of ping is to check whether we can reach the remote system and that the remote system can reach us back. In other words, initially, this was used to check network connectivity. However, we are more interested in its different uses: checking whether the remote system is online.

In simple terms, the ping command sends a packet to a remote system, and the remote system replies. This way, we can conclude that the remote system is online and that the network is working between the two systems.

In pickier definition, the ping is a command that sends an ICMP Echo packet to a remote system. If the remote system is online, and the ping packet was correctly routed and not blocked by any firewall, the remote system should send back an ICMP Echo Reply. Similarly, the ping reply should reach the first system if appropriately routed and not blocked by any firewall.

The objective of such a command is to ensure that the target system is online before we spend time carrying out more detailed scans to discover the running operating system and services.

Technically speaking, ping falls under the protocol **ICMP (Internet Control Message Protocol)**. ICMP supports many types of queries, but, in particular, we are interested in ping (ICMP echo/type 8) and ping reply (ICMP echo reply/type 0). Getting into ICMP details is not required to use ping.

Generally speaking, when we don’t get a ping reply back, there are a few explanations that would explain why we didn’t get a ping reply, for example:
* The destination computer is not responsive, possibly still booting up or turned off, or the OS has crashed.
* It is unplugged from the network, or there is a faulty network device across the path.
* A firewall is configured to block such packets. The firewall might be a piece of software running on the system itself or a separate network appliance. Note that MS Windows firewall blocks ping by default.
* Our system is unplugged from the network.

## Traceroute

As the name suggests, the `traceroute` command traces the route taken by the packets from our system to another host. The purpose of a traceroute is to find the IP addresses of the routers or hops that a packet traverses as it goes from our system to a target host.

This command also reveals the number of routers between the two systems. It is helpful as it indicates the number of hops (routers) between our system and the target host. However, note that the route taken by the packets might change as many routers use dynamic routing protocols that adapt to network changes.

On Linux, the `traceroute` command is used. On Windows, the `tracert` command is used.

There is no direct way to discover the path from our system to a target system. We rely on ICMP to "trick" the routers into revealing their IP addresses. We can accomplish this by using a small *Time To Live (TTL)* in the IP header field. Although the T in TTL stands for time, TTL indicates the maximum number of routers/hops that a packet can pass through before being dropped. TTL is not a maximum number of time units.

When a router receives a packet, it decrements the TTL by one before passing it to the next router. However, if the TTL reaches 0, it will be dropped, and an *ICMP Time-to-Live exceeded* would be sent to the original sender.

On Linux, `traceroute` will start by sending UDP datagrams within IP packets of TTL being 1. Thus, it causes the first router to encounter a `TTL=0` and send an *ICMP Time-to-Live exceeded* back. Hence, a TTL of 1 will reveal the IP address of the first router to us. Then it will send another packet with *TTL=2*. This packet will be dropped at the second router. And so on.

## Telnet

The **TELNET (Teletype Network)** protocol was developed in 1969 to communicate with a remote system via a command-line interface (CLI). Hence, the command `telnet` uses the TELNET protocol for remote administration. The default port used by `telnet` is 23.

From a security perspective, `telnet` sends all the data, including usernames and passwords, in cleartext. Sending in cleartext makes it easy for anyone, who has access to the communication channel, to steal the login credentials. The secure alternative is SSH (Secure SHell) protocol.

However, the telnet client, with its simplicity, can be used for other purposes. Knowing that telnet client relies on the TCP protocol, we can use Telnet to connect to any service and grab its banner.

## Netcat

Netcat or simply `nc` has different applications that can be of great value to a pentester. Netcat supports both TCP and UDP protocols. It can function as a client that connects to a listening port. Alternatively, it can act as a server that listens on a port of our choice. Hence, it is a convenient tool that we can use as a simple client or server over TCP or UDP.

