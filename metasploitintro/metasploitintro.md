# Metasploit: Introduction

## Description

An introduction to the main components of the Metasploit Framework.
* Category: Walkthrough

## Introduction to Metasploit

Metasploit is the most widely used exploitation framework. Metasploit is a powerful tool that can support all phases of a penetration testing engagement, from information gathering to post-exploitation.

Metasploit has two main versions:
* **Metasploit Pro**: The commercial version that facilitates the automation and management of tasks. This version has a graphical user interface (GUI).
* **Metasploit Framework**: The open-source version that works from the command line.

The Metasploit Framework is a set of tools that allow information gathering, scanning, exploitation, exploit development, post-exploitation, and more. While the primary usage of the Metasploit Framework focuses on the penetration testing domain, it is also useful for vulnerability research and exploit development.

The main components of the Metasploit Framework can be summarized as follows;
* **msfconsole**: The main command-line interface.
* **Modules**: supporting modules such as exploits, scanners, payloads, etc.
* **Tools**: Stand-alone tools that will help vulnerability research, vulnerability assessment, or penetration testing. Some of these tools are msfvenom, pattern_create and pattern_offset.

## Main Components of Metasploit

While using the Metasploit Framework, we will primarily interact with the Metasploit console. We can launch it from the terminal using the msfconsole command. The console will be our main interface to interact with the different modules of the Metasploit Framework.

Modules are small components within the Metasploit framework that are built to perform a specific task, such as exploiting a vulnerability, scanning a target, or performing a brute-force attack.

Before diving into modules, here are some recurring concepts:
* **Exploit**: A piece of code that uses a vulnerability present on the target system.
* **Vulnerability**: A design, coding, or logic flaw affecting the target system. The exploitation of a vulnerability can result in disclosing confidential information or allowing the attacker to execute code on the target system.
* **Payload**: An exploit will take advantage of a vulnerability. However, if we want the exploit to have the result we want, we need to use a payload. Payloads are the code that will run on the target system.

### Auxiliary

Any supporting module, such as scanners, crawlers and fuzzers, can be found here.

### Encoders

Encoders will allow us to encode the exploit and payload in the hope that a signature-based antivirus solution may miss them.

Signature-based antivirus and security solutions have a database of known threats. They detect threats by comparing suspicious files to this database and raise an alert if there is a match. Thus encoders can have a limited success rate as antivirus solutions can perform additional checks.

### Evasion

While encoders will encode the payload, they should not be considered a direct attempt to evade antivirus software. On the other hand, "evasion" modules will try that, with more or less success.

### Exploits

Exploits, neatly organized by target system.

### NOPs

NOPs (No OPeration) do nothing, literally. They are represented in the Intel x86 CPU family with 0x90, following which the CPU will do nothing for one cycle. They are often used as a buffer to achieve consistent payload sizes.

### Payloads

Payloads are codes that will run on the target system.

Exploits will leverage a vulnerability on the target system, but to achieve the desired result, we will need a payload.

Running command on the target system is already an important step but having an interactive connection that allows us to type commands that will be executed on the target system is better. Such an interactive command line is called a "shell". Metasploit offers the ability to send different payloads that can open shells on the target system.

There are 4 types of payloads:
* **Adapters**: An adapter wraps single payloads to convert them into different formats. For example, a normal single payload can be wrapped inside a Powershell adapter, which will make a single powershell command that will execute the payload.
* **Singles**: Self-contained payloads (add user, launch notepad.exe, etc.) that do not need to download an additional component to run.
* **Stagers**: Responsible for setting up a connection channel between Metasploit and the target system. Useful when working with staged payloads. "Staged payloads" will first upload a stager on the target system then download the rest of the payload (stage). This provides some advantages as the initial size of the payload will be relatively small compared to the full payload sent at once.
* **Stages**: Downloaded by the stager. This will allow us to use larger sized payloads.

Metasploit has a subtle way to help us identify single (also called "inline") payloads and staged payloads.
* generic/shell_reverse_tcp
* windows/x64/shell/reverse_tcp

Both are reverse Windows shells. The former is an inline (or single) payload, as indicated by the "_" between "shell" and "reverse". While the latter is a staged payload, as indicated by the "/" between "shell" and "reverse".

### Post

Post modules will be useful on the final stage of the penetration testing process listed above, post-exploitation.

## Msfconsole

As previously mentioned, the console will be our main interface to the Metasploit Framework. We can launch it using the `msfconsole` command on our terminal or any system the Metasploit Framework is installed on.

Msfconsole is managed by context; this means that unless set as a global variable, all parameter settings will be lost if we change the module we have decided to use.

### Search

One of the most useful commands in msfconsole is `search`. This command will search the Metasploit Framework database for modules relevant to the given search parameter. We can conduct searches using CVE numbers, exploit names (eternalblue, heartbleed, etc.), or target system.

The output of the `search` command provides an overview of each returned module. We notice the "name" column already gives more information than just the module name. We can see the type of module and the category of the module. We can use any module returned in a search result with the command `use` followed by the number at the beginning of the result line.

Another essential piece of information returned is in the rank column. Exploits are rated based on their reliability. The table below provides their respective descriptions:

| Ranking | Description |
| - | - |
| ExcellentRanking | The exploit will never crash the service. This is the case for SQL Injection, CMD execution, RFI, LFI, etc. No typical memory corruption exploits should be given this ranking unless there are extraordinary circumstances. |
| GreatRanking | The exploit has a default target AND either auto-detects the appropriate target or uses an application-specific return address AFTER a version check. |
| GoodRanking | The exploit has a default target and it is the "common case" for this type of software (English, Windows 7 for a desktop app, 2012 for server, etc.). |
| NormalRanking | The exploit is otherwise reliable, but depends on a specific version and can't (or doesn't) reliably auto-detect. |
| AverageRanking | The exploit is generally unreliable or difficult to exploit. |
| LowRanking | The exploit is nearly impossible to exploit (or under 50% success rate) for common platforms. |
| ManualRanking | The exploit is unstable or difficult to exploit and is basically a DoS. This ranking is also used when the module has no use unless specifically configured by the user. |

We can direct the search function using keywords such as type and platform.

Exploits take advantage of a vulnerability on the target system and may always show unexpected behavior. A low-ranking exploit may work perfectly, and an excellent ranked exploit may not, or worse, crash the target system.

## Summary

As we have seen so far, Metasploit is a powerful tool that facilitates the exploitation process. The exploitation process comprises three main steps: finding the exploit, customizing the exploit, and exploiting the vulnerable service.