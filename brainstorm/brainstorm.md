# Brainstorm

## Description

Reverse engineer a chat program and write a script to exploit a Windows machine.
* Difficulty: *Medium*
* Category: Buffer Overflow

## Scan Network

We are given the IP address of the target machine. Let's start by scanning the machine with Nmap.

![](nmap-failed.png)

The host is not responding. Maybe it is blocking the ping probes. Let's try to scan the machine without the ping scan.

![](nmap.png)

We found 3 open ports: 21, 3389, and 9999. Let's now scan the services running on these ports.

![](nmap-scan-services.png)

The FTP service is running on port 21, the RDP service is running on port 3389, and there is a beta version chat service running on port 9999. Let's start by checking the FTP service.

## Accessing Files

![](ftp-failed.png)

We kept trying to connect to the FTP service from our own Kali machine, but it was not working. We need to switch to the AttackBox to connect to the FTP service.

![](ftp-download-files.png)

We successfully connected to the FTP service and downloaded the files with the AttackBox. Now we transfer the files to our Kali machine.

![](files-transfered.png)

We have the files on our Kali machine. Let's check the files.

## Access

