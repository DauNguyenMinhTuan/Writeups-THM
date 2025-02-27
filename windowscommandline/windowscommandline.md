# Windows Command Line

## Description

Learn the essentials Windows commands.
* Category: Walkthrough

## Introduction

There are many advantages to using a CLI besides speed and efficiency. We will mention a few:
* **Lower resource usage:** CLIs require fewer system resources than graphics-intensive GUIs. In other words, we can run our CLI system on older hardware or systems with limited memory.
* **Automation:** While we can automate GUI tasks, creating a batch file or script with the commands we need to repeat is much easier.
* **Remote management:** CLI makes it very convenient to use SSH to manage a remote system such as a server, router, or an IoT device. This approach works well on slow network speeds and systems with limited resources.

### Learning Objectives

We will learn how to use the MS Windows Command Prompt `cmd.exe` to:
* Display basic system information
* Check and troubleshoot network configuration
* Manage files and folders
* Check running processes

## Basic System Information

Some basic commands to display system information are:
* `set` - Display all environment variables.
* `ver` - Display the Windows version.
* `systeminfo` - Display detailed system information.

## Network Troubleshooting

### Network Configuration

We can check the network configuration with `ipconfig` or `ipconfig /all`.

### Network Troubleshooting

One common troubleshooting task is checking if the server can access a particular server on the Internet using `ping`. Inspired by ping-pong, we send a specific ICMP packet and listen for a response. If a response is received, we know that we can reach the target and that the target can reach us.

Another useful command is `tracert`, which stands for *trace route*. The command traces the network route traversed to reach the target. Without getting into more details, it expects the routers on the path to notify us if they drop a packet because its time-to-live (TTL) has reached zero.

### More Networking Commands

One networking command worth knowing is `nslookup`. It looks up a host or domain and returns its IP address.

Another useful command is `netstat`. This command displays current network connections and listening ports. Some of the options are:
* `-h` - Display help.
* `-a` - Display all connections and listening ports.
* `-b` - Display the executable involved in creating each connection or listening port.
* `-n` - Display addresses and port numbers in numerical form.
* `-o` - Display the owning process ID associated with each connection.

## File and Disk Management

### Working with Directories

We can use the `cd` command to change directories, `dir` to list files and directories. Some useful options for `dir` are:
* `/a` - Display all files and directories, including hidden ones.
* `/s` - Display files in the specified directory and all subdirectories.

We can use `tree` to display the directory structure in a tree format.

To create a new directory, we use the `mkdir` command. To remove a directory, we use the `rmdir` command.

### Working with Files

We can see the contents of text files using `type` or `more`. The `copy` command allows us to copy files. `move` allows us to move files. Finally, `del` or `erase` allows us to delete files.

## Task and Process Management

We can list running processes with the `tasklist` command and kill a process with the `taskkill` command.

## Conclusion

In this room, we focused on the most practical commands for accessing a networked system over the command line.

There are others commands that can be useful for other tasks:
* `chkdsk` - Check and repair disk errors.
* `driverquery` - Display installed device drivers.
* `sfc /scannow` - Scan and repair system files.