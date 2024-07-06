# Network Services 2

## Description

Enumerating and Exploiting More Common Network Services & Misconfigurations
* Category: Walkthrough

### NFS

NFS stands for "**Network File System**" and allows a system to share directories and files with others over a network. By using NFS, users and programs can access files on remote systems almost as if they were local files. It does this by mounting all, or a portion of a file system on a server. The portion of the file system that is mounted can be accessed by clients with whatever privileges are assigned to each file.

#### How does NFS work?

First, the client will request to mount a directory from a remote host on a local directory just the same way it can mount a physical device. The mount service will then act to connect to the relevant mount daemon using RPC.

The server checks if the user has permission to mount whatever directory has been requested. It will then return a file handle which uniquely identifies each file and directory that is on the server.

If someone wants to access a file using NFS, an RPC call is placed to NFSD (NFS daemon) on the server. This call takes parameters such as:
* The file handle
* The name of the file
* The user's user ID
* The user's group ID

#### What runs NFS?

Using the NFS protocol, you can transfer files between computers running Windows and other non-Windows operating systems, such as Linux, MacOS or UNIX.

A computer running Windows Server can act as an NFS file server for other non-Windows client computers. Likewise, NFS allows a Windows-based computer running Windows Server to access files stored on a non-Windows NFS server.

### SMTP

SMTP stands for "**Simple Mail Transfer Protocol**". It is utilised to handle the sending of emails. In order to support email services, a protocol pair is required, comprising of SMTP and POP/IMAP. Together they allow the user to send outgoing mail and retrieve incoming mail, respectively.

The SMTP server performs three basic functions:
* Verify who is sending the emails
* Send the outgoing mail
* If the outgoing mail cannot be delivered it sends the message back to the sender

Most people will have encountered SMTP when configuring a new email address on some third-party email clients, such as Thunderbird; as when you configure a new email client, you will need to configure the SMTP server configuration in order to send outgoing emails.

#### POP and IMAP

POP, or "**Post Office Protocol**" and IMAP, "**Internet Message Access Protocol**" are both email protocols who are responsible for the transfer of email between a client and a mail server.

The main differences is in POP's more simplistic approach of downloading the inbox from the mail server, to the client. Where IMAP will synchronise the current inbox, with new mail on the server, downloading anything new. This means that changes to the inbox made on one computer, over IMAP, will persist if you then synchronise the inbox from another computer.

#### How does SMTP work?

Email delivery functions much the same as the physical mail delivery system. The user will supply the email (a letter) and a service (the postal delivery service), and through a series of steps- will deliver it to the recipients inbox (postbox). The role of the SMTP server in this service, is to act as the sorting office, the email (letter) is picked up and sent to this server, which then directs it to the recipient.

The journey of an email from sender to recipient is as follows:
1. The mail user agent, which is either your email client or an external program, connects to the SMTP server of your domain. This initiates the SMTP handshake. This connection works over the SMTP port which is usually 25. Once these connections have been made and validated, the SMTP session starts.
2. The process of sending mail can now begin. The client first submits the sender, and recipient's email address, the body of the email and any attachments, to the server.
3. The SMTP server then checks whether the domain name of the recipient and the sender is the same.
4. The SMTP server of the sender will make a connection to the recipient's SMTP server before relaying the email. If the recipient's server can't be accessed, or is not available, the email gets put into an SMTP queue.
5. The recipient's SMTP server will verify the incoming email. It does this by checking if the domain and user name have been recognised. The server will then forward the email to the POP or IMAP server.
6. The email will then show up in the recipient's inbox.

#### What runs SMTP?

SMTP Server software is readily available on Windows server platforms, with many other variants of SMTP being available to run on Linux.

