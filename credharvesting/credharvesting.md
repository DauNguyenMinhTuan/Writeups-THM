# Credentials Harvesting

## Description

Apply current authentication models employed in modern environments to a red team approach.
* Category: Walkthrough

## Introduction

Credential harvesting consists of techniques for obtaining credentials like login information, account names, and passwords. It is a technique of extracting credential information from a system in various locations such as clear-text files, registry, memory dumping, etc.

As a red teamer, gaining access to legitimate credentials has benefits:
* It can give access to systems (Lateral Movement).
* It makes it harder to detect our actions.
* It provides the opportunity to create and manage accounts to help achieve the end goals of a red team engagement.

## Credentials Harvesting

Credentials Harvesting is a term for gaining access to user and system credentials. It is a technique to look for or steal stored credentials, including network sniffing, where an attacker captures transmitted credentials.

Credentials can be found in a variety of different forms, such as:
* Accounts details (usernames and passwords)
* Hashes that include NTLM hashes, etc.
* Authentication Tickets: Tickets Granting Ticket (TGT), Ticket Granting Server (TGS)
* Any information that helps login into a system (private keys, etc.)

Generally speaking, there are two types of credential harvesting: external and internal. External credential harvesting most likely involves phishing emails and other techniques to trick a user into entering his username and password. Obtaining credentials through the internal network uses different approaches.

## Credential Access

Credential access is where adversaries may find credentials in compromised systems and gain access to user credentials. It helps adversaries to reuse them or impersonate the identity of a user. This is an important step for lateral movement and accessing other resources such as other applications or systems. Obtaining legitimate user credentials is preferred rather than exploiting systems using CVEs.

Credentials are stored insecurely in various locations in systems:
* Clear-text files
* Database files
* Memory
* Password managers
* Enterprise vaults
* Active Directory
* Network sniffing

### Clear-text Files

Attackers may search a compromised machine for credentials in local or remote file systems. Clear-text files could include sensitive information created by a user, containing passwords, private keys, etc. The MITRE ATT&CK framework defines it as **Unsecured Credentials: Credentials In Files (T1552.001)**.

The following are some of the types of clear-text files that an attacker may be interested in:
* Commands history
* Configuration files
* Other files related to Windows applications
* Backup files
* Shared files and folders
* Registry
* Source code

### Database Files

Applications utilize database files to read or write settings, configurations, or credentials. Database files are usually stored locally in Windows operating systems. These files are an excellent target to check and hunt for credentials.

### Password Managers

A password manager is an application to store and manage users' login information for local and Internet websites and services. Since it deals with users' data, it must be stored securely to prevent unauthorized access.

Examples of password managers applications:
* Built-in password managers (Windows)
* Third-party: KeePass, 1Password, LastPass

However, misconfiguration and security flaws are found in these applications that let adversaries access stored data. Various tools could be used during the enumeration stage to get sensitive data in password manager applications used by Internet browsers and desktop applications.

### Memory Dump

The Operating system's memory is a rich source of sensitive information that belongs to the Windows OS, users, and other applications. Data gets loaded into memory at run time or during the execution. Thus, accessing memory is limited to administrator users who fully control the system.

The following are examples of memory stored sensitive data, including:
* Clear-text credentials
* Cached passwords
* AD tickets

### Active Directory

Active Directory stores a lot of information related to users, groups, computers, etc. Thus, enumerating the Active Directory environment is one of the focuses of red team assessments. Active Directory has a solid design, but misconfiguration made by admins makes it vulnerable to various attacks.

The following are some of the Active Directory misconfigurations that may leak users' credentials.
* **Users' description:** Administrators set a password in the description for new employees and leave it there, which makes the account vulnerable to unauthorized access.
* **Group Policy SYSVOL:** Leaked encryption keys let attackers access administrator accounts.
* **NTDS:** Contains AD users' credentials, making it a target for attackers.
* **AD Attacks:** Misconfiguration makes AD vulnerable to various attacks.

### Network Sniffing

Gaining initial access to a target network enables attackers to perform various network attacks against local computers, including the AD environment. The Man-In-the-Middle attack against network protocols lets the attacker create a rogue or spoof trusted resources within the network to steal authentication information such as NTLM hashes.

## Local Windows Credentials

In general, Windows operating system provides two types of user accounts: Local and Domain. Local users' details are stored locally within the Windows file system, while domain users' details are stored in the centralized Active Directory.

### Keystrokes

Keylogger is a software or hardware device to monitor and log keyboard typing activities. Keyloggers were initially designed for legitimate purposes such as feedback for software development or parental control. However, they can be misused to steal data.

As a red teamer, hunting for credentials through keyloggers in a busy and interactive environment is a good option. If we know a compromised target has a logged-in user, we can perform keylogging using tools like the Metasploit framework or others.

### Security Accounts Manager (SAM)

The SAM is a Microsoft Windows database that contains local account information such as usernames and passwords. The SAM database stores these details in an encrypted format to make them harder to be retrieved. Moreover, it can not be read and accessed by any users while the Windows operating system is running. However, there are various ways and attacks to dump the content of the SAM database.

#### Metasploit's HashDump

The first method is using the built-in Metasploit Framework feature, hashdump, to get a copy of the content of the SAM database. The Metasploit framework uses in-memory code injection to the `LSASS.exe` process to dump copy hashes.

#### Volume Shadow Copy Service

The other approach uses the Microsoft Volume shadow copy service, which helps perform a volume backup while applications read/write on volumes.

More specifically, we will be using `wmic` to create a shadow volume copy. This has to be done through the command prompt with administrator privileges as follows:
1. Run the standard `cmd.exe` prompt with administrator privileges.
2. Execute the `wmic` command to create a copy shadow of `C:` drive
3. Verify the creation from step 2 is available.
4. Copy the SAM database from the volume we created in step 2

#### Registry Hives

Another possible method for dumping the SAM database content is through the Windows Registry. Windows registry also stores a copy of some of the SAM database contents to be used by Windows services. Luckily, we can save the value of the Windows registry using the `reg.exe` tool. As previously mentioned, we need two files to decrypt the SAM database's content.

Note if we compare the output against the NTLM hashes we got from Metasploit's Hashdump, the result is different. The reason is the other accounts belong to Active Directory, and their information is not stored in the System file we have dumped. To Decrypt them, we need to dump the SECURITY file from the Windows file, which contains the required files to decrypt Active Directory accounts.

Once we obtain NTLM hashes, we can try to crack them using Hashcat if they are guessable, or we can use different techniques to impersonate users using the hashes.

## Local Security Authority Subsystem Service (LSASS)

Local Security Authority Server Service (LSASS) is a Windows process that handles the operating system security policy and enforces it on a system. It verifies logged in accounts and ensures passwords, hashes, and Kerberos tickets.

Windows system stores credentials in the LSASS process to enable users to access network resources, such as file shares, SharePoint sites, and other network services, without entering credentials every time a user connects.

Thus, the LSASS process is a juicy target for red teamers because it stores sensitive information about user accounts. The LSASS is commonly abused to dump credentials to either escalate privileges, steal data, or move laterally.

Luckily for us, if we have administrator privileges, we can dump the process memory of LSASS. Windows system allows us to create a dump file, a snapshot of a given process. This could be done either with the Desktop access (GUI) or the command prompt. This attack is defined in the MITRE ATT&CK framework as **OS Credential Dumping: LSASS Memory (T1003)**.

### Graphic User Interface (GUI)

To dump any running Windows process using the GUI, open the Task Manager, and from the Details tab, find the required process, right-click on it, and select "Create dump file". Once the dumping process is finished, a pop-up message will show containing the path of the dumped file.

### Sysinternals Suite

An alternative way to dump a process if a GUI is not available to us is by using ProcDump. ProcDump is a Sysinternals process dump utility that runs from the command prompt.

### Mimikatz

Mimikatz is a well-known tool used for extracting passwords, hashes, PINs, and Kerberos tickets from memory using various techniques. Mimikatz is a post-exploitation tool that enables other useful attacks, such as pass-the-hash, pass-the-ticket, or building Golden Kerberos tickets.

Mimikatz deals with operating system memory to access information. Thus, it requires administrator and system privileges in order to dump memory and extract credentials.

LSASS process is running as a SYSTEM. Thus in order to access users' hashes, we need a system or local administrator permissions.

### Protected LSASS

In 2012, Microsoft implemented an LSA protection, to keep LSASS from being accessed to extract credentials from memory. To enable LSASS protection, we can modify the registry `RunAsPPL DWORD` value in `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa` to 1.

## Windows Credential Manager

Credential Manager is a Windows feature that stores logon-sensitive information for websites, applications, and networks. It contains login credentials such as usernames, passwords, and internet addresses. There are four credential categories:
* Web credentials contain authentication details stored in Internet browsers or other applications.
* Windows credentials contain Windows authentication details, such as NTLM or Kerberos.
* Generic credentials contain basic authentication details, such as clear-text usernames and passwords.
* Certificate-based credentials: These are authentication details based on certificates.

Note that authentication details are stored on the user's folder and are not shared among Windows user accounts. However, they are cached in memory.

### Accessing Credential Manager

We can access the Windows Credential Manager through GUI (Control Panel $\rarr$ User Accounts $\rarr$ Credential Manager) or the command prompt with `vaultcmd`.

In scenarios where GUI is not available, we start by enumerating if there are any stored credentials. By default, Windows has two vaults, one for Web and the other one for Windows machine credentials.

### Credentials Dumping

The VaultCmd is not able to show the password, but we can rely on other PowerShell Scripts.

### RunAs

An alternative method of taking advantage of stored credentials is by using RunAs. RunAs is a command-line built-in tool that allows running Windows applications or tools under different users' permissions.

The RunAs tool has various command arguments that could be used in the Windows system. The `/savecred` argument allows us to save the credentials of the user in Windows Credentials Manager (under the Windows Credentials section). So, the next time we execute as the same user, `runas` will not ask for a password.

### Mimikatz

Mimikatz is a tool that can dump clear-text passwords stored in the Credential Manager from memory. The steps are similar to those shown in the previous section (Memory dump), but we can specify to show the credentials manager section only this time.

---

The techniques discussed in this task also could be done through other tools such as Empire, Metasploit, etc.

## Domain Controller

### NTDS Domain Controller

New Technologies Directory Services (NTDS) is a database containing all Active Directory data, including objects, attributes, credentials, etc. The `NTDS.DTS` data consists of three tables as follows:
* Schema table: it contains types of objects and their relationships.
* Link table: it contains the object's attributes and their values.
* Data type: It contains users and groups.

NTDS is located in `C:\Windows\NTDS` by default, and it is encrypted to prevent data extraction from a target machine. Accessing the `NTDS.dit` file from the machine running is disallowed since the file is used by Active Directory and is locked. However, there are various ways to gain access to it.

It is important to note that decrypting the NTDS file requires a system Boot Key to attempt to decrypt LSA Isolated credentials, which is stored in the `SECURITY` file system. Therefore, we must also dump the security file containing all required files to decrypt.

### Ntdsutil

Ntdsutil is a Windows utility to used manage and maintain Active Directory configurations. It can be used in various scenarios such as:
* Restore deleted objects in Active Directory.
* Perform maintenance for the AD database.
* Active Directory snapshot management.
* Set Directory Services Restore Mode (DSRM) administrator passwords.

### Local Dumping (No Credentials)

This is usually done if we have no credentials available but have administrator access to the domain controller. Therefore, we will be relying on Windows utilities to dump the NTDS file and crack them offline. As a requirement, first, we assume we have administrator access to a domain controller.

To successfully dump the content of the NTDS file we need the following files:
* `C:\Windows\NTDS\ntds.dit`
* `C:\Windows\System32\config\SYSTEM`
* `C:\Windows\System32\config\SECURITY`

### Remote Dumping (With Credentials)

In the previous section, we discussed how to get hashes from memory with no credentials in hand. In this task, we will be showing how to dump a system and domain controller hashes remotely, which requires credentials, such as passwords or NTLM hashes. We also need credentials for users with administrative access to a domain controller or special permissions as discussed in the DC Sync section.

#### DC Sync

The DC Sync is a popular attack to perform within an Active Directory environment to dump credentials remotely. This attack works when an account (special account with necessary permissions) or AD admin account is compromised that has the following AD permissions:
* Replicating Directory Changes
* Replicating Directory Changes All
* Replicating Directory Changes in Filtered Set

An adversary takes advantage of these configurations to perform domain replication, commonly referred to as "DC Sync", or Domain Controller Sync.

## Local Administrator Password Solution (LAPS)

### Group Policy Preferences (GPP)

A Windows OS has a built-in **Administrator** account which can be accessed using a password. Changing passwords in a large Windows environment with many computers is challenging. Therefore, Microsoft implemented a method to change local administrator accounts across workstations using **Group Policy Preferences (GPP)**.

GPP is a tool that allows administrators to create domain policies with embedded credentials. Once the GPP is deployed, different XML files are created in the `SYSVOL` folder. `SYSVOL` is an essential component of Active Directory and creates a shared directory on an NTFS volume that all authenticated domain users can access with reading permission.

The issue was the GPP relevant XML files contained a password encrypted using *AES-256 bit encryption*. At that time, the encryption was good enough until Microsoft somehow published its private key on MSDN. Since Domain users can read the content of the `SYSVOL` folder, it becomes easy to decrypt the stored passwords. One of the tools to crack the `SYSVOL` encrypted password is `Get-GPPPassword`.

### Local Administrator Password Solution (LAPS)

In 2015, Microsoft removed storing the encrypted password in the `SYSVOL` folder. It introduced the Local Administrator Password Solution (LAPS), which offers a much more secure approach to remotely managing the local administrator password.

The new method includes two new attributes (`ms-mcs-AdmPwd` and `ms-mcs-AdmPwdExpirationTime`) of computer objects in the Active Directory. The `ms-mcs-AdmPwd` attribute contains a clear-text password of the local administrator, while the `ms-mcs-AdmPwdExpirationTime` contains the expiration time to reset the password. LAPS uses `admpwd.dll` to change the local administrator password and update the value of `ms-mcs-AdmPwd`.

It is important to note that in a real-world AD environment, the LAPS is enabled on specific machines only. Thus, we need to enumerate and find the right target computer as well as the right user account to be able to get the LAPS password.

## Other Attacks

In the previous tasks, the assumption is that we already had initial access to a system and were trying to obtain credentials from memory or various files within the Windows operating system. In other scenarios, it is possible to perform attacks in a victim network to obtain credentials.

### Kerberoasting

Kerberoasting is a common AD attack to obtain AD tickets that helps with persistence. In order for this attack to work, an adversary must have access to SPN (Service Principal Name) accounts such as IIS User, MSSQL, etc.

The Kerberoasting attack involves requesting a Ticket Granting Ticket (TGT) and Ticket Granting Service (TGS). This attack's end goal is to enable privilege escalation and lateral network movement.

### AS-REP Roasting

AS-REP Roasting is the technique that enables the attacker to retrieve password hashes for AD users whose account options have been set to **"Do not require Kerberos pre-authentication"**. This option relies on the old Kerberos authentication protocol, which allows authentication without a password. Once we obtain the hashes, we can try to crack it offline, and finally, if it is crackable, we got a password!

### SMB Relay Attack

The SMB Relay attack abuses the NTLM authentication mechanism (NTLM challenge-response protocol). The attacker performs a Man-in-the-Middle attack to monitor and capture SMB packets and extract hashes. For this attack to work, the SMB signing must be disabled. SMB signing is a security check for integrity and ensures the communication is between trusted sources.

### LLMNR/NBNS Poisoning

Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) help local network machines to find the right machine if DNS fails. For example, suppose a machine within the network tries to communicate with no existing DNS record (DNS fails to resolve). In that case, the machine sends multicast messages to all network machines asking for the correct address via LLMNR or NBT-NS.

The NBNS/LLMNR Poisoning occurs when an attacker spoofs an authoritative source on the network and responds to the Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) traffic to the requested host with host identification service.

The end goal for SMB relay and LLMNR/NBNS Poisoning attacks is to capture authentication NTLM hashes for a victim, which helps obtain access to the victim's account or machine.