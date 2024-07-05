# Network Services

## Description

Learn about, then enumerate and exploit a variety of network services and misconfigurations.
* Category: Walkthrough

### SMB

SMB - **Server Message Block Protocol** - is a client-server communication protocol used for sharing access to files, printers, serial ports and other resources on a network.

Servers make file systems and other resources (printers, named pipes, APIs) available to clients on the network. The SMB protocol is known as a response-request protocol, meaning that it transmits multiple messages between the client and server to establish a connection. Clients connect to servers using NetBIOS over TCP/IP (as specified in RFC1001 and RFC1002), NetBEUI or IPX/SPX.

Once a connection is established, clients can then send commands (SMBs) to the server that allow them to access shares, open files, read and write files.

Microsoft Windows operating systems since Windows 95 have included client and server SMB protocol support. Samba, an open source server that supports the SMB protocol, was released for Unix systems.

### Telnet

Telnet is an application protocol which allows you, with the use of a telnet client, to connect to and execute commands on a remote machine that's hosting a telnet server.

The telnet client will establish a connection with the server. The client will then become a virtual terminal- allowing you to interact with the remote host.

Telnet sends all messages in clear text and has no specific security mechanisms. Thus, in many applications and services, Telnet has been replaced by SSH in most implementations.

### FTP

FTP - **File Transfer Protocol** - is a protocol used to allow remote transfer of files over a network. To do this, it uses a client-server model and relays commands and data in a very efficient way.

A typical FTP session operates using 2 channels:
* A command channel (sometimes called the control channel) is used for transmitting and replying to commands.
* A data channel is used for transferring data.

FTP operates using a client-server protocol. The client initiates a connection with the server, the server validates whatever login credentials are provided and then opens the session. While the session is open, the client may execute FTP commands on the server.

The FTP server may support either Active or Passive connections, or both. In an Active FTP connection, the client opens a port and listens. The server is required to actively connect to it. In a Passive FTP connection, the server opens a port and listens (passively) and the client connects to it.

This separation of command information and data into separate channels is a way of being able to send commands to the server without having to wait for the current data transfer to finish. If both channels were interlinked, you could only enter commands in between data transfers, which wouldn't be efficient for either large file transfers, or slow internet connections.