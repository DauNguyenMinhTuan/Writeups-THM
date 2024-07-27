# Protocols and Servers

## Description

Learn about common protocols such as HTTP, FTP, POP3, SMTP and IMAP, along with related insecurities.
* Category: Walkthrough

## Telnet

The Telnet protocol is an application layer protocol used to connect to a virtual terminal of another computer. Using Telnet, a user can log into another computer and access its terminal (console) to run programs, start batch processes, and perform system administration tasks remotely.

Telnet protocol is relatively simple. When a user connects, they will be asked for a username and password. Upon correct authentication, the user will access the remote system’s terminal. Unfortunately, all this communication between the Telnet client and the Telnet server is not encrypted, making it an easy target for attackers.

Telnet is no longer considered a secure option, especially that anyone capturing our network traffic will be able to discover our usernames and passwords, which would grant them access to the remote system. The secure alternative is SSH.

## HyperText Transfer Protocol (HTTP)

Hypertext Transfer Protocol (HTTP) is the protocol used to transfer web pages. Our web browser connects to the webserver and uses HTTP to request HTML pages and images among other files and submit forms and upload various files. Anytime we browse the World Wide Web (WWW), we are certainly using the HTTP protocol.

HTTP sends and receives data as cleartext (not encrypted); therefore, we can use a simple tool, such as Telnet (or Netcat), to communicate with a web server and act as a "web browser". The key difference is that need to input the HTTP-related commands instead of the web browser doing that for us.

We need an HTTP server (webserver) and an HTTP client (web browser) to use the HTTP protocol. The web server will "serve" a specific set of files to the requesting web browser.

Three popular choices for HTTP servers are:
* Apache
* Internet Information Services (IIS)
* Nginx

Apache and Nginx are free and open-source software. However, IIS is closed source software and requires paying for a license.

There are many web browsers available. The most common ones are:
* Chrome by Google
* Edge by Microsoft
* Firefox by Mozilla
* Safari by Apple

Web browsers are generally free to install and use; furthermore, tech giants battle for a higher market share for their browsers.

## File Transfer Protocol (FTP)

File Transfer Protocol (FTP) was developed to make the transfer of files between different computers with different systems efficient.

FTP also sends and receives data as cleartext; therefore, we can use Telnet (or Netcat) to communicate with an FTP server and act as an FTP client.

A command like `STAT` can provide some added information. The `SYST` command shows the System Type of the target (UNIX in this case). `PASV` switches the mode to passive. It is worth noting that there are two modes for FTP:
* Active: In the active mode, the data is sent over a separate channel originating from the FTP server's port 20.
* Passive: In the passive mode, the data is sent over a separate channel originating from an FTP client's port above port number 1023.

The command `TYPE A` switches the file transfer mode to ASCII, while `TYPE I` switches the file transfer mode to binary. However, we cannot transfer a file using a simple client such as Telnet because FTP creates a separate connection for file transfer.

FTP client will initiate a connection to an FTP server, which listens on port 21 by default. All commands will be sent over the control channel. Once the client requests a file, another TCP connection will be established between them.

FTP servers and FTP clients use the FTP protocol. There are various FTP server software that we can select from if we want to host our FTP file server. Examples of FTP server software include:
* vsftpd
* ProFTPD
* uFTP

For FTP clients, in addition to the console FTP client commonly found on Linux systems, we can use an FTP client with GUI such as FileZilla. Some web browsers also support FTP protocol.

Because FTP sends the login credentials along with the commands and files in cleartext, FTP traffic can be an easy target for attackers.

## Simple Mail Transfer Protocol (SMTP)

Email is one of the most used services on the Internet. There are various configurations for email servers; for instance, we may set up an email system to allow local users to exchange emails with each other with no access to the Internet. However, we will consider the more general setup where different email servers connect over the Internet.

Email delivery over the Internet requires the following components:
1. Mail Submission Agent (MSA)
2. Mail Transfer Agent (MTA)
3. Mail Delivery Agent (MDA)
4. Mail User Agent (MUA)

To reach the recipient's inbox, the email needs to go through five steps:
1. A Mail User Agent (MUA), or simply an email client, has an email message to be sent. The MUA connects to a Mail Submission Agent (MSA) to send its message.
2. The MSA receives the message, checks for any errors before transferring it to the Mail Transfer Agent (MTA) server, commonly hosted on the same server.
3. The MTA will send the email message to the MTA of the recipient. The MTA can also function as a Mail Submission Agent (MSA).
4. A typical setup would have the MTA server also functioning as a Mail Delivery Agent (MDA).
5. The recipient will collect its email from the MDA using their email client.

In the same way, we need to follow a protocol to communicate with an HTTP server, and we need to rely on email protocols to talk with an MTA and an MDA. The protocols are:
1. Simple Mail Transfer Protocol (SMTP)
2. Post Office Protocol version 3 (POP3) or Internet Message Access Protocol (IMAP)

Simple Mail Transfer Protocol (SMTP) is used to communicate with an MTA server. Because SMTP uses cleartext, where all commands are sent without encryption, we can use a basic Telnet client to connect to an SMTP server and act as an email client (MUA) sending a message.

## Post Office Protocol 3 (POP3)

Post Office Protocol version 3 (POP3) is a protocol used to download the email messages from a Mail Delivery Agent (MDA) server. The mail client connects to the POP3 server, authenticates, downloads the new email messages before (optionally) deleting them.

POP3 commands are sent in cleartext. Using Telnet was enough to authenticate and retrieve an email message. As the username and password are sent in cleartext, any third party watching the network traffic can steal the login credentials.

In general, our mail client (MUA) will connect to the POP3 server (MDA), authenticate, and download the messages. Based on the default settings, the mail client deletes the mail message after it downloads it. The default behaviour can be changed from the mail client settings if we wish to download the emails again from another mail client. Accessing the same mail account via multiple clients using POP3 is usually not very convenient as one would lose track of read and unread messages. To keep all mailboxes synchronized, we need to consider other protocols, such as IMAP.

## Internet Message Access Protocol (IMAP)

Internet Message Access Protocol (IMAP) is more sophisticated than POP3. IMAP makes it possible to keep our email synchronized across multiple devices (and mail clients). In other words, if we mark an email message as read when checking our email on our smartphone, the change will be saved on the IMAP server (MDA) and replicated on our laptop when we synchronize our inbox.

IMAP sends login credentials in cleartext so anyone watching the network traffic would be able to know the username and password.