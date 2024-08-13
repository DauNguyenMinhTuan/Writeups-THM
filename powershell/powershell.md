# Hacking with Powershell

## Description

Learn the basics of PowerShell and PowerShell Scripting
* Category: Walkthrough

## What is Powershell?

Powershell is the Windows Scripting Language and shell environment built using the .NET framework.

This also allows Powershell to execute .NET functions directly from its shell. Most Powershell commands, called *cmdlets*, are written in .NET. Unlike other scripting languages and shell environments, the output of these *cmdlets* are objects - making Powershell somewhat object-oriented.

This also means that running cmdlets allows us to perform actions on the output object (which makes it convenient to pass output from one cmdlet to another). The normal format of a cmdlet is represented using Verb-Noun; for example, the cmdlet to list commands is called `Get-Command`.

Common verbs to use include:
* Get
* Start
* Stop
* Read
* Write
* New
* Out

## Basic Powershell Commands

### Get-Help

`Get-Help` displays information about a cmdlet. To get help with a particular command, run the following: `Get-Help Command-Name`.

We can also understand how exactly to use a command by passing in the `-Examples` flag.

### Get-Command

`Get-Command` gets all the cmdlets installed on the current Computer. The great thing about this cmdlet is that it allows for pattern matching like the following example: `Get-Command Verb-*` or `Get-Command *-Noun`.

### Object Manipulation

If we want to manipulate the output, we need to figure out a few things:
* Passing the output to other cmdlets
* Using specific object cmdlets to extract information

The Pipeline (`|`) is used to pass output from one cmdlet to another. A major difference compared to other shells is that Powershell passes an object to the next cmdlet instead of passing text or string to the command after the pipe. Like every object in object-oriented frameworks, an object will contain methods and properties. To view these details, we can use the `Get-Member` cmdlet.

### Creating Objects From Previous cmdlets

One way of manipulating objects is pulling out the properties from the output of a cmdlet and creating a new object. This is done using the `Select-Object` cmdlet.

### Filtering Objects

When retrieving output objects, we may want to select objects that match a very specific value. We can do this using the `Where-Object` to filter based on the value of properties.

The general format for using this cmdlet is `Verb-Noun | Where-Object -Property PropertyName -Operator Value` or `Verb-Noun | Where-Object { $_.PropertyName -Operator Value }`. The second version uses `$_` to iterate through every object passed to the cmdlet.

`-Operator` can be any of the following:
* `-Contains`: if any item in the property value is an exact match for the specified value.
* `-EQ`: if the property value is the same as the specified value.
* `-GT`: if the property value is greater than the specified value.

### Sort-Object

When a cmdlet outputs a lot of information, we may need to sort it to extract the information more efficiently. We do this by pipe-lining the output of a cmdlet to the `Sort-Object` cmdlet.

The format of the command should be `Verb-Noun | Sort-Object`.

## Enumeration

The first step when we have gained initial access to any machine would be to enumerate. We'll be enumerating the following:
* Users
* Basic Network Information
* File Permissions
* Registry Permissions
* Scheduled and Running Tasks
* Insecured Files