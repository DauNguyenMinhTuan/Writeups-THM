# Common Linux Privesc

## Description

A room explaining common Linux privilege escalation
* Category: Walkthrough

## Understanding Privesc

At it's core, Privilege Escalation usually involves going from a lower permission to a higher permission. More technically, it's the exploitation of a vulnerability, design flaw or configuration oversight in an operating system or application to gain unauthorized access to resources that are usually restricted from the users.

### Why is it important?

Rarely when doing a CTF or real-world penetration test, will we be able to gain a foothold (initial access) that affords us administrator access. Privilege escalation is crucial, because it lets us gain system administrator levels of access. This allow us to do many things, including:
* Reset passwords
* Bypass access controls to compromise protected data 
* Edit software configurations
* Enable persistence, so we can access the machine again later.
* Change privilege of users
* Get the cheeky root flag

## Direction of Privilege Escalation

There are two main privilege escalation variants.

**Horizontal privilege escalation**: This is where we expand our reach over the compromised system by taking over a different user who is on the same privilege level as us.

For instance, a normal user hijacking another normal user (rather than elevating to super user). This allows us to inherit whatever files and access that user has. This can be used, for example, to gain access to another normal privilege user, that happens to have an SUID file attached to their home directory which can then be used to get super user access.

**Vertical privilege escalation (privilege elevation)**: This is where we attempt to gain higher privileges or access, with an existing account that we have already compromised. For local privilege escalation attacks this might mean hijacking an account with administrator privileges or root privileges.

## Enumeration

### What is LinEnum?

LinEnum is a simple bash script that performs common commands related to privilege escalation, saving time and allowing more effort to be put toward getting root. It is important to understand what commands LinEnum executes, so that we are able to manually enumerate privesc vulnerabilities in a situation where we're unable to use LinEnum or other like scripts. In this room, we will explain what LinEnum is showing, and what commands can be used to replicate it.

### Understanding LinEnum Output

The LinEnum output is broken down into different sections:
* Kernel Information
* Read/Write sensitive files
* SUID files
* Crontab contents

## Abusing SUID/GUID Files

The first step in Linux privilege escalation exploitation is to check for files with the SUID/GUID bit set. This means that the file or files can be run with the permissions of the file(s) owner/group. In this case, as the super-user. We can leverage this to get a shell with these privileges!

### What is an SUID binary?

In Linux everything is a file, including directories and devices which have permissions to allow or restrict three operations i.e. read/write/execute. When we set permission for any file, we should be aware of the Linux users to whom we allow or restrict all three permissions.

The maximum number of bit that can be used to set permission for each user is 7, which is a combination of read (4) write (2) and execute (1) operation. For example, if we set permissions using `chmod` as 755, then it will be: `rwxr-xr-x`.

When special permission is given to each user it becomes SUID or SGID. When extra bit "4" is set to user(Owner) it becomes SUID (Set user ID) and when bit "2" is set to group it becomes SGID (Set Group ID).

Therefore, the permissions to look for when looking for SUID is: `rwsrwxrwx`. The same applies to SGID, but with `rwxrwsrwx`.

### Finding SUID Binaries

If we know that there is SUID capable files on the system, we want to find it using the command: `find / -perm -u=s -type f 2>/dev/null`. Let's break down this command:
* `find` - initiates the `find` command
* `/` - searches the whole file system
* `-perm` - searches for files with specific permissions
* `-u=s` - any of the permission bits mode are set for the file. Symbolic modes are accepted in this form.
* `-type f` - only search for files
* `2>/dev/null` - suppresses errors

## Exploiting Writeable /etc/passwd

### Understanding /etc/passwd

The `/etc/passwd` file stores essential information, which is required during login. In other words, it stores user account information. The `/etc/passwd` is a plain text file. It contains a list of the system's accounts, giving for each account some useful information like user ID, group ID, home directory, shell, and more.

The `/etc/passwd` file should have general read permission as many command utilities use it to map user IDs to user names. However, write access to the `/etc/passwd` must only limit for the `superuser/root` account. When it doesn't, or a user has erroneously been added to a write-allowed group, we have a vulnerability that can allow the creation of a root user that we can access.

### Understanding /etc/passwd format

The `/etc/passwd` file contains one entry per line for each user (user account) of the system. All fields are separated by a colon `:` symbol. Total of seven fields as follows:
1. **Username**: It is used when user logs in. It should be between 1 and 32 characters in length.
2. **Password**: An `x` character indicates that encrypted password is stored in `/etc/shadow` file. We need to use the `passwd` command to compute the hash of a password typed at the CLI or to store/update the hash of the password in `/etc/shadow` file.
3. **User ID (UID)**: Each user must be assigned a user ID (UID). UID 0 is reserved for root and UIDs 1-99 are reserved for other predefined accounts. Further UID 100-999 are reserved by system for administrative and system accounts/groups.
4. **Group ID (GID)**: The primary group ID (stored in `/etc/group` file)
5. **User ID Info**: The comment field. It allow us to add extra information about the users such as user’s full name, phone number etc.
6. **Home directory**: The absolute path to the directory the user will be in when they log in. If this directory does not exists then users directory becomes `/`.
7. **Command/shell**: The absolute path of a command or shell (`/bin/bash`). Typically, this is a shell.

### How to exploit a writable /etc/passwd

It's simple really, if we have a writable `/etc/passwd` file, we can write a new line entry according to the above formula and create a new user! We add the password hash of our choice, and set the UID, GID and shell to root. Allowing us to log in as our own root user!

## Escaping Vi Editor

### sudo -l

This exploit comes down to how effective our user account enumeration has been. Every time we have access to an account during a CTF scenario, we should use `sudo -l` to list what commands we're able to use as a super user on that account. Sometimes, we'll find that we're able to run certain commands as a root user without the root password. This can enable us to escalate privileges.

### Misconfigured Binaries and GTFOBins

If we find a misconfigured binary during our enumeration, or when we check what binaries a user account we have access to can access. A good place to look up how to exploit them is **GTFOBins**.

GTFOBins is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. It provides a really useful breakdown of how to exploit a misconfigured binary and is the first place we should look if we find one on a CTF or Pentest.

## Exploiting Crontab

### What is Cron?

The Cron daemon is a long-running process that executes commands at specific dates and times. We can use this to schedule activities, either as one-time events or as recurring tasks. We can create a crontab file containing commands and instructions for the Cron daemon to execute.

### How to view what Cronjobs are active

We can use the command `cat /etc/crontab` to view what cron jobs are scheduled. This is something we should always check manually whenever we get a chance, especially if LinEnum, or a similar script, doesn't find anything.

### Format of a Cronjob

Cronjobs exist in a certain format, being able to read that format is important if we want to exploit a cron job:
* \# = ID
* m = Minute
* h = Hour
* dom = Day of Month
* mon = Month
* dow = Day of Week
* user = What user the command will run as
* command = What command should be run

## Exploiting PATH Variable

### What is PATH?

PATH is an environmental variable in Linux and Unix-like operating systems which specifies directories that hold executable programs. When the user runs any command in the terminal, it searches for executable files with the help of the PATH Variable in response to commands executed by a user.

It is very simple to view the Path of the relevant user with help of the command `echo $PATH`.

### How does this let us escalate privileges?

Let's say we have an SUID binary. Running it, we can see that it’s calling the system shell to do a basic process like list processes with `ps`. Unlike in our previous SUID example, in this situation we can't exploit it by supplying an argument for command injection, so what can we do to try and exploit this?

We can re-write the PATH variable to a location of our choosing! So when the SUID binary calls the system shell to run an executable, it runs one that we've written instead!

As with any SUID file, it will run this command with the same privileges as the owner of the SUID file! If this is root, using this method we can run whatever commands we like as root!