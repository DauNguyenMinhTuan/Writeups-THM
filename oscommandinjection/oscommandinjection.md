# Command Injection

## Description

Learn about a vulnerability allowing us to execute commands through a vulnerable app, and its remediations.
* Category: Walkthrough

## Introduction (What is Command Injection?)

Command injection is the abuse of an application's behaviour to execute commands on the operating system, using the same privileges that the application on a device is running with.

Command injection is also often known as **"Remote Code Execution" (RCE)** because of the ability to remotely execute code within an application. These vulnerabilities are often the most lucrative to an attacker because it means that the attacker can directly interact with the vulnerable system.

Command injection was one of the top ten vulnerabilities reported by Contrast Security’s AppSec intelligence report in 2019. (Contrast Security AppSec., 2019). Moreover, the OWASP framework constantly proposes vulnerabilities of this nature as one of the top ten vulnerabilities of a web application (OWASP framework).

## Discovering Command Injection

This vulnerability exists because applications often use functions in programming languages such as PHP, Python and NodeJS to pass data to and to make system calls on the machine’s operating system.

## Exploiting Command Injection

We can often determine whether or not command injection may occur by the behaviours of an application.

Applications that use user input to populate system commands with data can often be combined in unintended behaviour. For example, the shell operators `;`, `&` and `&&` will combine two (or more) system commands and execute them both.

Command Injection can be detected in mostly one of two ways:
* Blind command injection
* Verbose command injection

### Blind Command Injection

This type of injection is where there is no direct output from the application when testing payloads. We will have to investigate the behaviours of the application to determine whether or not our payload was successful.

### Verbose Command Injection

This type of injection is where there is direct feedback from the application once we have tested a payload. For example, running the `whoami` command to see what user the application is running under. The web application will output the username on the page directly.

### Detecting Blind Command Injection

Blind command injection is when command injection occurs. However, there is no output visible, so it is not immediately noticeable.

For this type of command injection, we will need to use payloads that will cause some time delay. For example, the `ping` and `sleep` commands are significant payloads to test with. Using `ping` as an example, the application will hang for x seconds in relation to how many pings we have specified.

Another method of detecting blind command injection is by forcing some output. This can be done by using redirection operators such as `>`. For example, we can tell the web application to execute commands such as `whoami` and redirect that to a file. We can then use a command such as `cat` to read this newly created file’s contents.

Testing command injection this way is often complicated and requires quite a bit of experimentation, significantly as the syntax for commands varies between Linux and Windows.

The `curl` command is a great way to test for command injection. This is because we are able to use curl to deliver data to and from an application in our payload.

### Detecting Verbose Command Injection

Detecting command injection this way is arguably the easier method of the two. Verbose command injection is when the application gives us feedback or output as to what is happening or being executed.

### Useful payloads for Linux

| **Payload** | **Description** |
| - | - |
| `whoami` | See what user the application is running under. |
| `ls` | List the contents of the current directory. We may be able to find files such as configuration files, environment files (tokens and application keys), and many more valuable things. |
| `ping` | This command will invoke the application to hang. This will be useful in testing an application for blind command injection. |
| `sleep` | This is another useful payload in testing an application for blind command injection, where the machine does not have `ping` installed. |
| `nc` | Netcat can be used to spawn a reverse shell onto the vulnerable application. We can use this foothold to navigate around the target machine for other services, files, or potential means of escalating privileges. |

### Useful payloads for Windows

| **Payload** | **Description** |
| - | - |
| `whoami` | See what user the application is running under. |
| `dir` | List the contents of the current directory. We may be able to find files such as configuration files, environment files (tokens and application keys), and many more valuable things. |
| `ping` | This command will invoke the application to hang. This will be useful in testing an application for blind command injection. |
| `timeout` | This command will also invoke the application to hang. It is also useful for testing an application for blind command injection if the `ping` command is not installed. |

## Remediating Command Injection

Command injection can be prevented in a variety of ways. Everything from minimal use of potentially dangerous functions or libraries in a programming language to filtering input without relying on a user’s input.

### Vulnerable Functions

In PHP, many functions interact with the operating system to execute commands via shell including:
* `exec()`
* `passthru()`
* `system()`

These functions take input such as a string or user data and will execute whatever is provided on the system. Any application that uses these functions without proper checks will be vulnerable to command injection.

### Input Sanitisation

Sanitising any input from a user that an application uses is a great way to prevent command injection. This is a process of specifying the formats or types of data that a user can submit. For example, an input field that only accepts numerical data or removes any special characters such as `>`, `&` and `/`.

### Bypassing Filters

Applications will employ numerous techniques in filtering and sanitising data that is taken from a user's input. These filters will restrict us to specific payloads. However, we can abuse the logic behind an application to bypass these filters. For example, an application may strip out quotation marks; we can instead use the hexadecimal value of this to achieve the same result.