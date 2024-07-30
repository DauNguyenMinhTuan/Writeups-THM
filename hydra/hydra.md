# Hydra

## Description

Learn about and use Hydra, a fast network logon cracker, to bruteforce and obtain a website's credentials.
* Category: Walkthrough

## Hydra introduction

Hydra is a brute force online password cracking program, a quick system login password "hacking" tool.

Hydra can run through a list and “brute force” some authentication services. Imagine trying to manually guess someone's password on a particular service (SSH, Web Application Form, FTP or SNMP) - we can use Hydra to run through a password list and speed this process up for us, determining the correct password.

According to its official repository, Hydra supports, i.e., has the ability to brute force the following protocols: "Asterisk, AFP, Cisco AAA, Cisco auth, Cisco enable, CVS, Firebird, FTP, HTTP-FORM-GET, HTTP-FORM-POST, HTTP-GET, HTTP-HEAD, HTTP-POST, HTTP-PROXY, HTTPS-FORM-GET, HTTPS-FORM-POST, HTTPS-GET, HTTPS-HEAD, HTTPS-POST, HTTP-Proxy, ICQ, IMAP, IRC, LDAP, MEMCACHED, MONGODB, MS-SQL, MYSQL, NCP, NNTP, Oracle Listener, Oracle SID, Oracle, PC-Anywhere, PCNFS, POP3, POSTGRES, Radmin, RDP, Rexec, Rlogin, Rsh, RTSP, SAP/R3, SIP, SMB, SMTP, SMTP Enum, SNMP v1+v2+v3, SOCKS5, SSH (v1 and v2), SSHKEY, Subversion, TeamSpeak (TS2), Telnet, VMware-Auth, VNC and XMPP."

## Using Hydra

### Hydra Commands

The options we pass into Hydra depend on which service (protocol) we're attacking. For example, if we wanted to brute force FTP with the username being `user` and a password list being `passlist.txt`, we'd use the following command: `hydra -l user -P passlist.txt ftp://<IP>`.

### Post Web Form

We can use Hydra to brute force web forms too. We must know which type of request it is making; GET or POST methods are commonly used. We can use our browser's network tab (in developer tools) to see the request types or view the source code.

```bash
sudo hydra <username> <wordlist> 10.10.71.99 http-post-form "<path>:<login_credentials>:<invalid_response>"
```

Example:
```bash
hydra -l <username> -P <wordlist> 10.10.71.99 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V
```