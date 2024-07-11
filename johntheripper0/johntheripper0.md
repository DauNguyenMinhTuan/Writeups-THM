# John The Ripper

## Description

Learn how to use John the Ripper - An extremely powerful and adaptable hash cracking tool.
* Category: Walkthrough

## John who?

John the Ripper is one of the most well known, well-loved and versatile hash cracking tools out there. It combines a fast cracking speed, with an extraordinary range of compatible hash types.

### What are Hashes?

A hash is a way of taking a piece of data of any length and  representing it in another form that is a fixed length. This masks the original value of the data. This is done by running the original data through a hashing algorithm. There are many popular hashing algorithms, such as MD4,MD5, SHA1 and NTLM.

### What makes Hashes secure?

Hashing functions are designed as one-way functions. In other words, it is easy to calculate the hash value of a given input; however, it is a difficult problem to find the original input given the hash value. By "difficult", we mean that it is computationally infeasible. This has its roots in mathematics and P vs NP.

In computer science, P and NP are two classes of problems that help us understand the efficiency of algorithms:
* **P (Polynomial Time)**: Class P covers the problems whose solution can be found in polynomial time. Consider sorting a list in increasing order. The longer the list, the longer it would take to sort; nonetheless, the increase in time is not exponential.
* **NP (Nondeterministic Polynomial Time)**: Problems in the class NP are those for which a given solution can be checked quickly, even though finding the solution itself might be hard. In fact, we don't know if there is a fast algorithm to find the solution in the first place.

Abstractly it means that the algorithm to hash the value will be "P" and can therefore be calculated reasonably. However an un-hashing algorithm would be "NP" and intractable to solve, meaning that it cannot be computed in a reasonable time using standard computers.

### Where John comes in...

Even though the algorithm itself is not feasibly reversible. That doesn't mean that cracking the hashes is impossible.

If we have the hashed version of the password and its hashing algorithm, we can use that hashing algorithm to hash a large number of words, called a dictionary. We can then compare these hashes to the one we're trying to crack, to see if any of them match. If they do, we now know what word corresponds to that hash and we've cracked it!

This process is called a **dictionary attack** and John the Ripper, or John as it's commonly shortened to, is a tool to allow us to conduct fast brute force attacks on a large array of different hash types.

## Cracking Basic Hashes

The basic syntax of John the Ripper is `john [options] [hashfile]`.

### Automatic Cracking

John has built-in features to detect what type of hash it's being given, and to select appropriate rules and formats to crack it. The syntax for this is `john --wordlist=[wordlist] [hashfile]`.

### Format-Specific Cracking

Syntax: `john --format=[format] --wordlist=[wordlist] [hashfile]`.

## Cracking Windows Authentication Hashes

### NTHash / NTLM

NThash is the hash format that modern Windows Operating System machines will store user and service passwords in. It's also commonly referred to as "NTLM" which references the previous version of Windows format for hashing passwords known as "LM", thus "NT/LM".

A little bit of history, the NT designation for Windows products originally meant "New Technology" to denote products that were not built up from the MS-DOS Operating System. Eventually, the "NT" line became the standard Operating System type to be released by Microsoft and the name was dropped, but it still lives on in the names of some Microsoft technologies.

We can acquire NTHash/NTLM hashes by dumping the SAM database on a Windows machine, by using a tool like `Mimikatz` or from the Active Directory database: NTDS.dit. We may not have to crack the hash to continue privilege escalation as we can often conduct a "pass the hash" attack instead, but sometimes hash cracking is a viable option if there is a weak password policy.

## Cracking /etc/shadow Hashes

The `/etc/shadow` file is the file on Linux machines where password hashes are stored. It also stores other information, such as the date of last password change and password expiration information. It contains one entry per line for each user or user account of the system. This file is usually only accessible by the root user.

### Unshadowing

John can be very particular about the formats it needs data in to be able to work with it, for this reason,in order to crack `/etc/shadow` passwords, we must combine it with the `/etc/passwd` file in order for John to understand the data it's being given. To do this, we use a tool built into the John suite of tools called `unshadow`. The basic syntax for this is `unshadow [passwdfile] [shadowfile] > [outputfile]`.

### Cracking

We're then able to feed the output from `unshadow` directly into John. We should not need to specify a mode here as we have made the input specifically for John, however in some cases we will need to specify the format as we have done previously using: `--format=sha512crypt`

`john --wordlist=[wordlist] --format=sha512crypt [outputfile]`

## Single Crack Mode

John the Ripper has a mode called Single Crack mode. In this mode, John uses only the information provided in the username, to try and work out possible passwords heuristically, by slightly changing the letters and numbers contained within the username.

### Word Mangling

John is building it's own dictionary based on the information that it has been fed and uses a set of rules called "mangling rules" which define how it can mutate the word it started with to generate a wordlist based off of relevant factors for the target we're trying to crack. This is exploiting how poor passwords can be based off of information about the username, or the service they're logging into.

### GECOS

John's implementation of word mangling also features compatibility with the Gecos fields of the UNIX operating system, and other UNIX-like operating systems such as Linux.

What are Gecos? As in the last section, we mentioned that the `/etc/passwd` file contains information about users. The Gecos field is a field in the `/etc/passwd` file that is used to store information about the user. John can take information stored in those records, such as full name and home directory name to add in to the wordlist it generates when cracking `/etc/shadow` hashes with single crack mode.

### Using Single Crack Mode

`john --single --format=[format] [hashfile]`

## Custom Rules

As we journeyed through our exploration of what John can do in Single Crack Mode, we may have some ideas about what some good mangling patterns would be, or what patterns our passwords often use that could be replicated with a certain mangling pattern.

The good news is we can define our own sets of rules, which John will use to dynamically create passwords. This is especially useful when we know more information about the password structure of whatever our target is.

### Common Custom Rules

Many organisations will require a certain level of password complexity to try and combat dictionary attacks. However, we can exploit the fact that most users will be predictable in adapting to these requirements.

Now this does meet the password complexity requirements, however as an attacker we can exploit the fact we know the likely position of these added elements to create dynamic passwords from our wordlists.

### How to create Custom Rules

Custom rules are defined in the `john.conf` file, usually located in `/etc/john/john.conf` if we have installed John using a package manager.

The first line `List.Rules:[rule name]` is the name of the rule set we're defining. This is what we will use to reference the rule set when we're running John.

We then use a regex style pattern match to define where in the word will be modified. Some basic and most common rules are:
* `c` - Capitalize the character positionally
* `l` - Lowercase the character positionally
* `Az` - Takes the word and appends the defined characters
* `A0` - Takes the word and prepends the defined characters

These can be used in combination to define where and what in the word we want to modify.

Lastly, we then need to define what characters should be appended, prepended or otherwise included, we do this by adding character sets in square brackets `[ ]` in the order they should be used. These directly follow the modifier patterns inside of double quotes `" "`. Here are some common examples:

* `[0-9]` - include numbers 0-9
* `[0]` - include only the number 0
* `[a-z]` - include only lowercase letters
* `[A-Z]` - include only uppercase letters
* `[A-z]` - include both uppercase and lowercase letters
* `[a]` - include only the letter a
* `[!£$%@]` - include the characters !£$%@

Example:
```bash
# The password is "Polopassword1!"
[List.Rules:PoloPassword]
cAz"[0-9] [!£$%@]"
```

### Using Custom Rules

`john --wordlist=[wordlist] --rules=[rule name] [hashfile]`

## Cracking Password-Protected ZIP Files

We can use John to crack the password on password protected Zip files. Again, we're going to be using a separate part of the john suite of tools to convert the zip file into a format that John will understand.

### Zip2John

Similarly to the unshadow tool that we used previously, we're going to be using the zip2john tool to convert the zip file into a hash format that John is able to understand, and hopefully crack. The basic usage of this tool is `zip2john [options] [zipfile] > [outputfile]`.

### Cracking

We're then able to take the file we output from zip2john and feed it directly into John. The syntax for this is `john --wordlist=[wordlist] [outputfile]`.

## Cracking Password-Protected RAR Archives

The process is very similar to cracking password-protected zip files.

## Cracking SSH Keys with John

Let's explore one more use of John that comes up semi-frequently in CTF challenges. Using John to crack the SSH private key password of `id_rsa` files.

Unless configured otherwise, we authenticate our SSH login using a password. However, we can configure key-based authentication, which lets us use our private key, `id_rsa`, as an authentication key to login to a remote machine over SSH. However, doing so will often require a password. Here we will be using John to crack this password to allow authentication over SSH using the key.

### SSH2John

As the name suggests `ssh2john` converts the id_rsa private key that we use to login to the SSH session into hash format that `john` can work with.

The process is very similar to the previous tools we've used.