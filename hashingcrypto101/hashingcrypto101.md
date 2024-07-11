# Hashing - Crypto 101

## Description

An introduction to Hashing, as part of a series on crypto.
* Category: Walkthrough

## Key Terms

* **Plaintext**: Data before encryption or hashing, often text but not always as it could be a photograph or other file instead.
* **Encodings**: This is not a form of encryption, just a form of data representation like base64 or hexadecimal. Immediately reversible.
* **Hash**: A hash is the output of a hash function. Hashing can also be used as a verb, "to hash", meaning to produce the hash value of some data.
* **Brute Force**: Attacking cryptography by trying every different password or every different key.
* **Cryptanalysis**: Attacking cryptography by finding a weakness in the underlying maths.

## What is a hash function?

Hash functions are quite different from encryption. There is no key, and it’s meant to be impossible (or very very difficult) to go from the output back to the input.

A hash function takes some input data of any size, and creates a summary or "digest" of that data. The output is a fixed size. It’s hard to predict what the output will be for any input and vice versa. Good hashing algorithms will be (relatively) fast to compute, and slow to reverse (Go from output and determine input). Any small change in the input data (even a single bit) should cause a large change in the output.

The output of a hash function is normally raw bytes, which are then encoded. Common encodings for this are base 64 or hexadecimal. Decoding these won’t give us anything useful.

### What's a hash collision?

A hash collision is when 2 different inputs give the same output. Hash functions are designed to avoid this as best as they can, especially being able to engineer (create intentionally) a collision.

Due to the pigeonhole effect, collisions are not avoidable. The pigeonhole effect is basically, there are a set number of different output values for the hash function, but we can give it any size input. As there are more inputs than outputs, some of the inputs must give the same output. If we have 128 pigeons and 96 pigeonholes, some of the pigeons are going to have to share.

MD5 and SHA1 have been attacked, and made technically insecure due to engineering hash collisions. However, no attack has yet given a collision in both algorithms at the same time so if we use the MD5 hash AND the SHA1 hash to compare, we will see they’re different.

Due to these, we shouldn't trust either algorithm for hashing passwords or data.

## Uses for hashing

Hashing is used for 2 main purposes in Cyber Security. To verify integrity of data or for verifying passwords.

### Hashing for password verification

Most webapps need to verify a user's password at some point. Storing these passwords in plain text would be bad. Knowing some people, they use the same password for everything including their banking, so leaking these would be really really bad.

We can't encrypt the passwords, as the key has to be stored somewhere. If someone gets the key, they can just decrypt the passwords.

This is where hashing comes in. What if, instead of storing the password, we just store the hash of the password? This means we never have to store the user's password, and if our database was leaked then an attacker would have to crack each password to find out what the password was. That sounds fairly useful.

There's just one problem with this. What if two users have the same password? As a hash function will always turn the same input into the same output, we will store the same password hash for each user. That means if someone cracks that hash, they get into more than one account. It also means that someone can create a *"Rainbow table"* to break the hashes.

A rainbow table is a lookup table of hashes to plaintexts, so we can quickly find out what password a user had just from the hash. A rainbow table trades time taken to crack a hash for hard disk space, but they do take time to create.

Websites like Crackstation internally use HUGE rainbow tables to provide fast password cracking for hashes without salts. Doing a lookup in a sorted list of hashes is really quite fast, much much faster than trying to crack the hash.

### Protecting against rainbow tables

To protect against rainbow tables, we add a salt to the passwords. The salt is randomly generated and stored in the database, unique to each user. In theory, we could use the same salt for all users but that means that duplicate passwords would still have the same hash, and a rainbow table could still be created specific passwords with that salt.

The salt is added to either the start or the end of the password before it’s hashed, and this means that every user will have a different password hash even if they have the same password. Hash functions like bcrypt and sha512crypt handle this automatically. Salts don’t need to be kept private.

## Recognising password hashes

There exists automated hash recognition tools but they're not perfect. It is advised to use a healthy combination of tools.

If a hash is found in a web application database, it's more likely to be MD5 than NTLM. Automated hash recognition tools often get these hash types mixed up, which highlights the importance of learning ourself.

Unix style password hashes are very easy to recognise, as they have a prefix. The prefix tells us the hashing algorithm used to generate the hash. The standard format is `$format$rounds$salt$hash`.

On Linux, password hashes are stored in /etc/shadow. This file is normally only readable by root. They used to be stored in /etc/passwd, and were readable by everyone.

Here are some common prefixes:
| Prefix | Algorithm |
|-|-|
| \$1\$ | md5crypt (use in Cisco stuff and older Linux/Unix system) |
| \$2\$, \$2a\$, \$2b\$, \$2x\$, \$2y\$ | bcrypt (popular for web applications) |
| \$6\$ | sha256crypt (default for most Linux/Unix systems) |

Windows passwords are hashed using NTLM, which is a variant of MD4. They're visually identical to MD4 and MD5 hashes, so it's very important to use context to work out the hash type.

On Windows, password hashes are stored in the SAM. Windows tries to prevent normal users from dumping them, but tools like `mimikatz` exist for this. Importantly, the hashes found there are split into NT hashes and LM hashes.

## Password Cracking

We can't decrypt password hashes. They're not encrypted. We have to crack the hashes by hashing a large number of different inputs, potentially adding the salt if there is one and comparing it to the target hash.

### Why crack on GPUs?

Graphics cards have thousands of cores. Although they can’t do the same sort of work that a CPU can, they are very good at some of the maths involved in hash functions. This means we can use a graphics card to crack most hash types much more quickly.

Some hashing algorithms, notably bcrypt, are designed so that hashing on a GPU is about the same speed as hashing on a CPU which helps them resist cracking.

### Cracking on VMs?

Virtual machines normally don’t have access to the host's graphics card. If we want to run `hashcat`, it's best to run it on our host.

**John the ripper** uses CPU by default and as such, works in a VM out of the box although we may get better speeds running it on the host OS as it will have more threads and no overhead from running in a VM.

Never use `--force` for `hashcat` as it can lead to false positives and false negatives.

## Hashing for integrity checking

Hashing can be used to check that files haven't been changed. If we put the same data in, we always get the same data out. If even a single bit changes, the hash will change a lot. This means we can use it to check that files haven't been modified or to make sure that they have downloaded correctly. We can also use hashing to find duplicate files, if two pictures have the same hash then they are the same picture.

### HMACs

HMAC is a method of using a cryptographic hashing function to verify the authenticity and integrity of data. The TryHackMe VPN uses HMAC-SHA512 for message authentication, which you can see in the terminal output.

A HMAC can be used to ensure that the person who created the HMAC is who they say they are (authenticity), and that the message hasn’t been modified or corrupted (integrity). They use a secret key, and a hashing algorithm in order to produce a hash.