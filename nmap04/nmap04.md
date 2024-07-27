# Nmap Post Port Scans

## Description

Learn how to leverage Nmap for service and OS detection, use Nmap Scripting Engine (NSE), and save the results.
* Category: Walkthrough

## Service Detection

Once Nmap discovers open ports, we can probe the available port to detect the running service. Further investigation of open ports is an essential piece of information as the pentester can use it to learn if there are any known vulnerabilities of the service.

Adding `-sV` to our Nmap command will collect and determine service and version information for the open ports. We can control the intensity with `--version-intensity LEVEL` where the level ranges between 0, the lightest, and 9, the most complete. `-sV --version-light` has an intensity of 2, while `-sV --version-all` has an intensity of 9.

It is important to note that using `-sV` will force Nmap to proceed with the TCP 3-way handshake and establish the connection. The connection establishment is necessary because Nmap cannot discover the version without establishing a connection fully and communicating with the listening service. In other words, stealth SYN scan `-sS` is not possible when -sV option is chosen.

## OS Detection and Traceroute

### OS Detection

Nmap can detect the Operating System (OS) based on its behaviour and any telltale signs in its responses. OS detection can be enabled using `-O`; this is an uppercase O as in OS.

The OS detection is very convenient, but many factors might affect its accuracy. First and foremost, Nmap needs to find at least one open and one closed port on the target to make a reliable guess. Furthermore, the guest OS fingerprints might get distorted due to the rising use of virtualization and similar technologies. Therefore, always take the OS version with a grain of salt.

### Traceroute

If we want Nmap to find the routers between us and the target, just add `--traceroute`. Nmap's traceroute works slightly different than the `traceroute` command found on Linux and macOS or `tracert` found on MS Windows. Standard traceroute starts with a packet of low TTL (Time to Live) and keeps increasing until it reaches the target. Nmap's traceroute starts with a packet of high TTL and keeps decreasing it.

## Nmap Scripting Engine (NSE)

A script is a piece of code that does not need to be compiled. In other words, it remains in its original human-readable form and does not need to be converted to machine language.

Many programs provide additional functionality via scripts; moreover, scripts make it possible to add custom functionality that did not exist via the built-in commands. Similarly, Nmap provides support for scripts using the Lua language. A part of Nmap, Nmap Scripting Engine (NSE) is a Lua interpreter that allows Nmap to execute Nmap scripts written in Lua language. However, we don't need to learn Lua to make use of Nmap scripts.

We can specify to use any or a group of these installed scripts; moreover, we can install other user's scripts and use them for our scans. Let’s begin with the default scripts. We can choose to run the scripts in the default category using `--script=default` or simply adding `-sC`. In addition to default, categories include:
| **Script Category** | **Description** |
| - | - |
| `auth` | Authentication related scripts |
| `broadcast` | Discover hosts by sending broadcast messages |
| `brute` | Performs brute-force password auditing against logins |
| `default` | Default scripts, same as `-sC` |
| `discovery` | Retrieve accessible information, such as database tables and DNS names |
| `dos` | Detects servers vulnerable to Denial of Service (DoS) |
| `exploit` | Attempts to exploit various vulnerable services |
| `external` | Checks using a third-party service, such as Geoplugin and Virustotal |
| `fuzzer` | Launch fuzzing attacks |
| `intrusive` | Intrusive scripts such as brute-force attacks and exploitation |
| `malware` | Scans for backdoors |
| `safe` | Safe scripts that won’t crash the target |
| `version` | Retrieve service versions |
| `vuln` | Checks for vulnerabilities or exploit vulnerable services |

Some scripts belong to more than one category. Moreover, some scripts launch brute-force attacks against services, while others launch DoS attacks and exploit systems. Hence, it is crucial to be careful when selecting scripts to run if we don't want to crash services or exploit them.

## Saving the Output

Whenever we run a Nmap scan, it is only reasonable to save the results in a file. Selecting and adopting a good naming convention for our filenames is also crucial. The number of files can quickly grow and hinder our ability to find a previous scan result. The three main formats are:
1. Normal
2. Grepable
3. XML

There is a fourth one that is not recommended: Script Kiddie.

### Normal

The normal format is similar output we get on the screen when scanning a target. We can save out scan in normal format by using `-oN FILENAME`. N stands for normal.

### Grepable

The grepable format has its name from the command `grep`. `grep` stands for **Global Regular Expression Printer**. In simple terms, it makes filtering the scan output for specific keywords or terms efficient. We can save the scan result in grepable format using `-oG FILENAME`. The main reason is that Nmap wants to make each line meaningful and complete when the user applies grep. As a result, in grepable output, the lines are so long and are not convenient to read compared to normal output.

### XML

The third format is XML. We can save the scan results in XML format using `-oX FILENAME`. The XML format would be most convenient to process the output in other programs. Conveniently enough, we can save the scan output in all three formats using `-oA FILENAME` to combine `-oN`, `-oG`, and `-oX` for normal, grepable, and XML.

### Script Kiddie

This format is useless if we want to search the output for any interesting keywords or keep the results for future reference. However, we can use it to save the output of the scan `nmap -sS 127.0.0.1 -oS FILENAME`, display the output filename, and look ***31337*** in front of friends who are not tech-savvy.