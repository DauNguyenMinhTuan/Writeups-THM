# Introductory Networking

## Descriptions

An introduction to networking theory and basic networking tools.
* Category: Walkthrough

### The OSI Model: An Overview

The **OSI (Open Systems Interconnection) Model** is a standardised model which we use to demonstrate the theory behind computer networking. In practice, it's actually the more compact TCP/IP model that real-world networking is based off; however the OSI model, in many ways, is easier to get an initial understanding from.

The OSI model consists of 7 layers:
|**OSI**|
|:--:|
|Application Layer|
|Presentation Layer|
|Session Layer|
|Transport Layer|
|Network Layer|
|Data Link Layer|
|Physical Layer|

Layer 7: **Application Layer**  
The Application Layer of the OSI Model essentially provides networking options to programs running on a computer. It works almost exclusively with applications, providing an interface for them to use in order to transmit data. When data is given to the application layer, it is passed down into the presentation layer.

Layer 6: **Presentation Layer**  
The presentation layer receives data from the application layer. This data tends to be in a format that the application understands, but it's not necessarily in a standardised format that could be understood by the application layer in the *receiving* computer.  
The presentation layer translates the data into a standardised format, as well as handling any encryption, compression or other transformations to the data. With this complete, the data is passed down to the session layer.

Layer 5: **Session Layer**  
When the session layer receives the correctly formatted data from the presentation layer, it looks to see if it can set up a connection with the other computer across the network.  
If it can't then it sends back an error and the process goes no further. If a session can be established then it's the job of the session layer to maintain it, as well as co-operate with the session layer of the remote computer in order to synchronise communications. This is what allows you to make multiple requests to different endpoints simultaneously without all the data getting mixed up.  
When the session layer has successfully logged a connection between the host and remote computer the data is passed down to the transport Layer.

Layer 4: **Transport Layer**  
The transport layer chooses the protocol over which the data will be transmitted. The 2 most common protocols in transport layer are **TCP (Transmission Control Protocol)** and **UDP (User Datagram Protocol)**.  
TCP is a *connection-based* protocol which means a connection between computers is established and maintained for the duration of the request. This allows for a reliable transmission, as the connection can be used to ensure that the packets all get to the right place. It also allows the two computers to remain in constant communication to ensure that the data is sent at an acceptable speed, and that any lost data is re-sent.  
With UDP, packets of data are essentially thrown at the receiving computer.  
TCP would usually be chosen for situations where accuracy is favoured over speed. UDP would be used in situations where speed is more important.  
With a protocol selected, the transport layer then divides transmission up into pieces (*segments* over TCP, *datagrams* over UDP), which makes it easier to transmit the message successfully.

Layer 3: **Network Layer**  
The network layer is responsible for locating the destination of your request. It's the network layer that takes the IP address for the page and figures out the best route to take. At this stage we're working with what is referred to as Logical addressing (i.e. IP addresses) which are still software controlled. Logical addresses are used to provide order to networks, categorising them and allowing us to properly sort them. Currently the most common form of logical addressing is the IPV4 format.

Layer 2: **Data Link Layer**  
The data link layer focuses on the physical addressing of the transmission. It receives a packet from the network layer (that includes the IP address for the remote computer) and adds in the physical (MAC) address of the receiving endpoint. Inside every network enabled computer is a Network Interface Card (NIC) which comes with a unique MAC (Media Access Control) address to identify it.  
MAC addresses are set by the manufacturer and literally burnt into the card; they can't be changed -- although they can be spoofed. When information is sent across a network, it's actually the physical address that is used to identify where exactly to send the information.  
Additionally, it's also the job of the data link layer to present the data in a format suitable for transmission. The data link layer also serves an important function when it receives data, as it checks the received information to make sure that it hasn't been corrupted during transmission.

Layer 1: **Physical Layer**  
The physical layer is right down to the hardware of the computer. This is where the electrical pulses that make up data transfer over a network are sent and received. It's the job of the physical layer to convert the binary data of the transmission into signals and transmit them across the network, as well as receiving incoming signals and converting them back into binary data.

### Encapsulation

As data is passed down each layer of model, more information containing details specific to the layer is added. This process is referred to as encapsulation, by which the data can be sent from one computer to another.

The encapsulated data is referred differently at each layer. In the top 3 layers, the data is referred to as *data*. In the transport layer, the data is referred to as a *segment* or a *datagram*. In the network layer, the data is referred to as a *packet*. In the data link layer, the data is referred to as a *frame*. Finally, in the physical layer, the data is referred to as *bits*.

When the data reaches the destination computer, it goes through a reverse process called *decapsulation*. Starting from the physical layer, the data is stripped of the added information as it moves up the layers all the way to the application layer.

The process of encapsulation and decapsulation is very important as it gives us a standardised method to send data. This means that all transmissions will consistently follow the same methodology, allowing any network enabled device to send a request to any other reachable device and be sure that it will be understood regardless of whether they are from the same manufacturer; use the same operating system; or any other factors.

### The TCP/IP Model

The TCP/IP model is very similar to the OSI model. It is a few years older and serves as the basis for real-world networking. The TCP/IP model consists of 4 layers that cover the same range of functions as the 7 layers of the OSI model.

|TCP/IP|
|:--:|
|Application|
|Transport|
|Internet|
|Network Interface|

***Note:** Some recent sources split the TCP/IP model into five layers, thus breaking the Network Interface layer into Data Link and Physical layers (as with the OSI model). This is accepted and well-known; however, it is not officially defined (unlike the original four layers which are defined in RFC1122).*

<style type="text/css">
	table.tableizer-table {
		font-size: 12px;
		border: 1px solid #CCC; 
		font-family: Arial, Helvetica, sans-serif;
	} 
	.tableizer-table td {
		padding: 4px;
		margin: 3px;
		border: 1px solid #CCC;
	}
	.tableizer-table th {
		background-color: #8B008B; 
		color: #FFF;
		font-weight: bold;
        border: 1px solid #CCC;
	}
</style>
<table class="tableizer-table">
    <thead>
        <tr class="tableizer-firstrow">
            <th>OSI</th><th>TCP/IP</th>
        </tr>
    </thead>
    <tbody>
		<tr>
			<td>Application</td>
			<td rowspan="3">Application</td>
		</tr>
		<tr>
			<td>Presentation</td>
		</tr>
		<tr>
			<td>Session</td>
		</tr>
		<tr>
			<td>Transport</td>
			<td>Transport</td>
		</tr>
		<tr>
			<td>Network</td>
			<td>Internet</td>
		</tr>
		<tr>
			<td>Data Link</td>
			<td rowspan="2">Network Interface</td>
		</tr>
		<tr>
			<td>Physical</td>
		</tr>
	</tbody>
</table>

The process of encapsulation and decapsulation works exactly the same way with the TCP/IP model as it does with the OSI model. At each layer, a header is added during encapsulation and removed during decapsulation.

TCP/IP takes its name from the two most important of these: the **Transmission Control Protocol** that controls the flow of data between two endpoints, and the **Internet Protocol**, which controls how packets are addressed and sent.

TCP is a *connection-based* protocol, which means before sending any data, you must first form a stable connection between two computers. The process of forming this connection is called a *three-way handshake*.

When you attempt to make a connection, your computer first sends a request containing a *SYN* (short for *synchronise*) bit to the server to indicate that it wants to establish a connection. The server then responds with a request containing a SYN bit as well as another *"acknowledgement"* bit called *ACK*. Finally, your computer sends a packet containing the ACK bit, confirming that the connection has been setup successfully.

With the three-way handshake completed, data can be reliably transmitted between the two computers. Any lost or corrupted data is re-sent, thus leading to a connection which appears to be lossless.

#### History

At first there was no standardisation. Then in 1982, the American Department of Defence (DoD) introduced the TCP/IP model to provide a standard for all manufacturer to follow. Later the ISO (International Standards Organisation) introduced the OSI model. The OSI model was more detailed and had more layers, but the TCP/IP model was already in use and was more practical. The OSI model is still used as a teaching tool, but the TCP/IP model is the one that is used in the real world.

### Ping

**Ping** is a command-line utility that is used to test whether a connection to a remote source is possible.

Ping works using the ICMP protocol. The ICMP protocol works on the Network layer of the OSI Model, thus the Internet layer of the TCP/IP model. The basic syntax for ping is `ping <TARGET>`

### Traceroute

**Traceroute** is a command-line utility that is used to trace the route that a packet takes to reach a destination. The Internet is made up of many different servers and endpoints all networked up to each other. Traceroute allows you to see every intermediate steps between your computer and the requested resource. The basic syntax for traceroute is `traceroute <TARGET>`

### WHOIS

**WHOIS** is a command-line utility that is used to look up information about a domain. WHOIS queries are made to WHOIS servers, which are databases that store information about domain names and the people who own them. The basic syntax for WHOIS is `whois <DOMAIN>`.

### Dig

URLs are converted into IP addresses using a TCP/IP protocol called DNS (Domain Name System). When a request is made, first, your computer checks its local *"Hosts file"* for an explicit IP $\rarr$ domain mapping. If it can't find one, it checks its local DNS cache.

If a mapping is still not found, the request is sent to a *recursive* DNS server. These are known by the router. These servers are maintained by ISPs and big companies such as Google, OpenDNS, etc. These servers also have cache for popular domains. If the requested domain is not found in the cache, the recursive server will query the *root* DNS server.

Before 2004, there were precisely 13 root name DNS servers in the world. The root name servers keep track of the DNS servers in the next level down and redirect the request to the appropriate one. The lower level servers are called *Top-Level Domain* (TLD) servers.

Top-Level Domain servers are split up into extensions. Requests are sent to the appropriate TLD server based on the extension of the domain. For example, if the domain is `example.com`, the request is sent to the `.com` TLD server. As with root servers, TLD servers keep track of the next level down: *Authoritative* DNS servers.

Authoritative DNS servers are used to store DNS records for domains directly. In other words, every domain in the world will have its DNS records stored on an Authoritative name server somewhere or another; they are the source of the information. When your request reaches the authoritative name server for the domain you're querying, it will send the relevant information back to you, allowing your computer to connect to the IP address behind the domain you requested.

**Dig** is a command-line utility that is used to query DNS servers to look up information about a domain. The syntax for dig is `dig <DOMAIN> @<DNS-SERVER-IP>`.