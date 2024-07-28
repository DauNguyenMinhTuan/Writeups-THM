# Protocols and Servers 2

## Description

Learn about attacks against passwords and cleartext traffic; explore options for mitigation via SSH and SSL/TLS.
* Category: Walkthrough

## Introduction

Servers implementing cleartext protocols are subject to different kinds of attack, such as:
1. Sniffing Attack (Network Packet Capture)
2. Man-In-The-Middle Attack (MITM)
3. Password Attack (Authentication Attack)
4. Vulnerabilities

From a security perspective, we always need to think about what we aim to protect; consider the security triad: Confidentiality, Integrity, and Availability (CIA).

Confidentiality refers to keeping the contents of the communications accessible to the intended parties. Integrity is the idea of assuring any data sent is accurate, consistent, and complete when reaching its destination. Finally, availability refers to being able to access the service when we need it.

Different parties will put varying emphasis on these three. For instance, confidentiality would be the highest priority for an intelligence agency. Online banking will put most emphasis on the integrity of transactions. Availability is of the highest importance for any platform making money by serving ads.

Knowing that we are protecting the Confidentiality, Integrity, and Availability (CIA), an attack aims to cause Disclosure, Alteration, and Destruction (DAD).

These attacks directly affect the security of the system. For instance, network packet capture violates confidentiality and leads to the disclosure of information. A successful password attack can also lead to disclosure. On the other hand, a Man-in-the-Middle (MITM) attack breaks the system's integrity as it can alter the communicated data. These attacks are integral to the protocol design and server implementation.

Vulnerabilities are of a broader spectrum, and exploited vulnerabilities have different impacts on the target systems. For instance, exploiting a Denial of Service (DoS) vulnerability can affect the system's availability, while exploiting a Remote Code Execution (RCE) vulnerability can lead to more severe damages. It is important to note that a vulnerability by itself creates a risk; damage can occur only when the vulnerability is exploited.

## Sniffing Attack

Sniffing attack refers to using a network packet capture tool to collect information about the target. When a protocol communicates in cleartext, the data exchanged can be captured by a third party to analyse. A simple network packet capture can reveal information, such as the content of private messages and login credentials, if the data isn't encrypted in transit.

A sniffing attack can be conducted using an Ethernet (802.3) network card, provided that the user has proper permissions (root permissions on Linux and administrator privileges on MS Windows). There are many programs available to capture network packets. We consider the following:
1. **Tcpdump** is a free open source command-line interface (CLI) program that has been ported to work on many operating systems.
2. **Wireshark** is a free open source graphical user interface (GUI) program available for several operating systems, including Linux, macOS and MS Windows.
3. **Tshark** is a CLI alternative to Wireshark.

There are several specialized tools for capturing passwords and even complete messages; however, this can still be achieved by Tcpdump and Wireshark with some added effort.

In brief, any protocol that uses cleartext communication is susceptible to this kind of attack. The only requirement for this attack to succeed is to have access to a system between the two communicating systems. This attack requires attention; the mitigation lies in adding an encryption layer on top of any network protocol. In particular, Transport Layer Security (TLS) has been added to HTTP, FTP, SMTP, POP3, IMAP and many others. For remote access, Telnet has been replaced by the secure alternative Secure Shell (SSH).

## Man-In-The-Middle (MITM) Attack

A Man-in-the-Middle (MITM) attack occurs when a victim (A) believes they are communicating with a legitimate destination (B) but is unknowingly communicating with an attacker (E).

This attack is relatively simple to carry out if the two parties do not confirm the authenticity and integrity of each message. In some cases, the chosen protocol does not provide secure authentication or integrity checking; moreover, some protocols have inherent insecurities that make them susceptible to this kind of attack.

Any time we browse over HTTP, we are susceptible to a MITM attack, and the scary thing is that we cannot recognize it. Many tools would aid us in carrying out such an attack, such as Ettercap and Bettercap.

MITM can also affect other cleartext protocols such as FTP, SMTP, and POP3. Mitigation against this attack requires the use of cryptography. The solution lies in proper authentication along with encryption or signing of the exchanged messages. With the help of Public Key Infrastructure (PKI) and trusted root certificates, Transport Layer Security (TLS) protects from MITM attacks.

## Transport Layer Security (TLS)

SSL (Secure Sockets Layer) started when the world wide web started to see new applications, such as online shopping and sending payment information. Netscape introduced SSL in 1994, with SSL 3.0 being released in 1996. But eventually, more security was needed, and TLS (Transport Layer Security) protocol was introduced in 1999.

The common protocols we have covered so far send the data in cleartext; this makes it possible for anyone with access to the network to capture, save and analyze the exchanged messages. The protocols we have covered so far in this room are on the application layer. Consider the ISO/OSI model; we can add encryption to our protocols via the presentation layer. Consequently, data will be presented in an encrypted format (ciphertext) instead of its original form.

Because of the close relation between SSL and TLS, one might be used instead of the other. However, TLS is more secure than SSL, and it has practically replaced SSL. We could have dropped SSL and just written TLS instead of SSL/TLS, but we will continue to mention the two to avoid any ambiguity because the term SSL is still in wide use. However, we can expect all modern servers to be using TLS.

An existing cleartext protocol can be upgraded to use encryption via SSL/TLS. We can use TLS to upgrade HTTP, FTP, SMTP, POP3, and IMAP, to name a few. The following table lists the protocols we have covered and their default ports before and after the encryption upgrade via SSL/TLS. The list is not exhaustive; however, the purpose is to help us better understand the process.

| **Protocol** | **Default Port** | **Secured Protocol** | **Default Port with TLS** |
| - | - | - | - |
| HTTP | 80 | HTTPS | 443 |
| FTP | 21 | FTPS | 990 |
| SMTP | 25 | SMTPS | 465 |
| POP3 | 110 | POP3S | 995 |
| IMAP | 143 | IMAPS | 993 |

Considering the case of HTTP. Initially, to retrieve a web page over HTTP, the web browser would need at least perform the following two steps:
1. Establish a TCP connection with the remote web server.
2. Send HTTP requests to the web server, such as GET and POST requests.

HTTPS requires an additional step to encrypt the traffic. The new step takes place after establishing a TCP connection and before sending HTTP requests. This extra step can be inferred from the OSI model. Consequently, HTTPS requires at least the following three steps:
1. Establish a TCP connection.
2. Establish SSL/TLS connection.
3. Send HTTP requests to the webserver.

To establish an SSL/TLS connection, the client needs to perform the proper handshake with the server.

After establishing a TCP connection with the server, the client establishes an SSL/TLS connection. The terms might look complicated, but we can simplify the four steps as:
1. The client sends a ClientHello to the server to indicate its capabilities, such as supported algorithms.
2. The server responds with a ServerHello, indicating the selected connection parameters. The server provides its certificate if server authentication is required. The certificate is a digital file to identify itself; it is usually digitally signed by a third party. Moreover, it might send additional information necessary to generate the master key, in its ServerKeyExchange message, before sending the ServerHelloDone message to indicate that it is done with the negotiation.
3. The client responds with a ClientKeyExchange, which contains additional information required to generate the master key. Furthermore, it switches to use encryption and informs the server using the ChangeCipherSpec message.
4. The server switches to use encryption as well and informs the client in the ChangeCipherSpec message.

A client was able to agree on a secret key with a server that has a public certificate. This secret key was securely generated so that a third party monitoring the channel wouldn't be able to discover it. Further communication between the client and the server will be encrypted using the generated key.

Consequently, once an SSL/TLS handshake has been established, HTTP requests and exchanged data won't be accessible to anyone watching the communication channel.

As a final note, for SSL/TLS to be effective, especially when browsing the web over HTTPS, we rely on public certificates signed by certificate authorities trusted by our systems. This way, our browser ensures that it is communicating with the correct server, and a MITM attack cannot occur.

In a certificate, we can see information such as:
1. To whom is the certificate issued? That is the name of the company that will use this certificate.
2. Who issued the certificate? This is the certificate authority that issued this certificate.
3. Validity period. We don't want to use a certificate that has expired, for instance.

Luckily, we don't have to check the certificate manually for every site we visit; our web browser will do it for us. Our web browser will ensure that we are talking with the correct server and ensure that our communication is secure, thanks to the server's certificate.

## Secure Shell (SSH)

Secure Shell (SSH) was created to provide a secure way for remote system administration. In other words, it lets we securely connect to another system over the network and execute commands on the remote system. Put simply, the "S" in SSH stands for secure, which can be summarized simply as:
1. We can confirm the identity of the remote server
2. Exchanged messages are encrypted and can only be decrypted by the intended recipient
3. Both sides can detect any modification in the messages

The above three points are ensured by cryptography. In more technical terms, they are part of confidentiality and integrity, made possible through the proper use of different encryption algorithms.

To use SSH, we need an SSH server and an SSH client. The SSH server listens on port 22 by default. The SSH client can authenticate using:
* A username and a password
* A private and public key (after the SSH server is configured to recognize the corresponding public key)

On Linux, macOS, and MS Windows builds after 2018, we can connect to an SSH server using the following command `ssh <USERNAME>@<IP>`. This command will try to connect to the server of IP address with the username. If an SSH server is listening on the default port, it will ask us to provide the password for username. Once authenticated, the user will have access to the target server's terminal.

Note that if this is the first time we connect to this system, we will need to confirm the fingerprint of the SSH server’s public key to avoid man-in-the-middle (MITM) attacks. As explained earlier, MITM takes place when a malicious party, E, situates itself between A and B, and communicates with A, pretending to be B, and communicates with B pretending to be A, while A and B think that they are communicating directly with each other. In the case of SSH, we don't usually have a third party to check if the public key is valid, so we need to do this manually.

We can use SSH to transfer files using SCP (Secure Copy Protocol) based on the SSH protocol.

FTP could be secured using SSL/TLS by using the FTPS protocol which uses port 990. It is worth mentioning that FTP can also be secured using the SSH protocol which is the SFTP protocol. By default this service listens on port 22, just like SSH.

## Password Attack

Many protocols require us to authenticate. Authentication is proving who we claim to be. When we are using protocols such as POP3, we should not be given access to the mailbox before verifying our identity.

Authentication, or proving our identity, can be achieved through one of the following, or a combination of two:
1. Something you *know*, such as password and PIN code.
2. Something you *have*, such as a SIM card, RFID card, and USB dongle.
3. Something you *are*, such as fingerprint and iris.

If we revisit the communication with several previous servers using protocols such as Telnet, SSH, POP3, and IMAP, we always need a password to gain access. Based on the 150 million usernames and passwords leaked from the Adobe breach in 2013, the top ten passwords are:
* 123456
* 123456789
* password
* adobe123
* 12345678
* qwerty
* 1234567
* 111111
* photoshop
* 123123

Only two passwords are related to Adobe and its products, but the rest are generic. 123456, 1234567, 12345678, and 123456789 are still common choices for many users. Others haven't realized yet that qwerty is not secret, and it is used by many as their password.

Attacks against passwords are usually carried out by:
1. Password Guessing: Guessing a password requires some knowledge of the target, such as their pet's name and birth year.
2. Dictionary Attack: This approach expands on password guessing and attempts to include all valid words in a dictionary or a wordlist.
3. Brute Force Attack: This attack is the most exhaustive and time-consuming where an attacker can go as far as trying all possible character combinations, which grows fast (exponential growth with the number of characters).

Over time, hackers have compiled list after list containing leaked passwords from data breaches. One example is RockYou’s list of breached passwords. The choice of the word list should depend on our knowledge of the target. For instance, a French user might use a French word instead of an English one. Consequently, a French word list might be more promising.

We want an automated way to try the common passwords or the entries from a word list; here comes THC Hydra. Hydra supports many protocols, including FTP, POP3, IMAP, SMTP, SSH, and all methods related to HTTP. The general command-line syntax is: `hydra -l username -P wordlist.txt server service` where we specify the following options:
* `-l username`: `-l` should precede the `username`, i.e., the login name of the target.
* `-P wordlist.txt`: `-P` precedes the `wordlist.txt` file, which is a text file containing the list of passwords we want to try with the provided username.
* `server` is the hostname or IP address of the target server.
* `service` indicates the service which we are trying to launch the dictionary attack.

There are some extra optional arguments that we can add:
* `-s PORT` to specific a non-default port for the service in question.
* `-V` or `-vV` for verbose, making Hydra show the username and password combinations that are being tried. This verbosity is very convinient to see the progress if we are not confident with our command-line syntax.
* `-t n` where n is the number of parallel connections to the target. `-t 16` will create 16 threads used to connect to the target.
* `-d`, for debugging, to get more detailed information about what's going on. The debugging output can save us much frustration; for instance, if Hydra tries to connect to a closed port and timing out, `-d` will reveal this right away.

In summary, attacks against login systems can be carried out efficiently using a tool, such as THC Hydra combined with a suitable word list. Mitigation against such attacks can be sophisticated and depends on the target system. A few of the approaches include:
* Password Policy: Enforces minimum complexity constraints on the passwords set by the user.
* Account Lockout: Locks the account after a certain number of failed attempts.
* Throttling Authentication Attempts: Delays the response to a login attempt. A couple of seconds of delay is tolerable for someone who knows the password, but they can severely hinder automated tools.
* Using CAPTCHA: Requires solving a question difficult for machines. It works well if the login page is via a graphical user interface (GUI). (Note that CAPTCHA stands for Completely Automated Public Turing test to tell Computers and Humans Apart.)
* Requiring the use of a public certificate for authentication. This approach works well with SSH, for instance.
* Two-Factor Authentication: Ask the user to provide a code available via other means, such as email, smartphone app or SMS.
* There are many other approaches that are more sophisticated or might require some established knowledge about the user, such as IP-based geolocation.

Using a combination of the above approaches is an excellent approach to protect against password attacks.