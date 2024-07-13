# Encryption - Crypto 101

## Description

An introduction to encryption, as part of a series on crypto.
* Category: Walkthrough

## Types of Encryption

The two main categories of Encryption are symmetric and asymmetric.

**Symmetric encryption** uses the same key to encrypt and decrypt the data. Examples of Symmetric encryption are **DES** (Broken) and **AES**. These algorithms tend to be faster than asymmetric cryptography, and use smaller keys.

**Asymmetric encryption** uses a pair of keys, one to encrypt and the other in the pair to decrypt. Examples are **RSA** and **Elliptic Curve Cryptography**. Normally these keys are referred to as a public key and a private key. Data encrypted with the private key can be decrypted with the public key, and vice versa. Our private key needs to be kept private, hence the name. Asymmetric encryption tends to be slower and uses larger keys, for example RSA typically uses 2048 to 4096 bit keys.

RSA and Elliptic Curve cryptography are based around different mathematically difficult (intractable) problems, which give them their strength.

## RSA - Rivest Shamir Adleman

RSA is based on the mathematically difficult problem of working out the factors of a large number. It’s very quick to multiply two prime numbers together, say 17*23 = 391, but it’s quite difficult to work out what two prime numbers multiply together to make 14351 (113x127 for reference).

## Establish Keys Using Asymmetric Cryptography

A very common use of asymmetric cryptography is exchanging keys for symmetric encryption.

Asymmetric encryption tends to be slower, so for things like HTTPS symmetric encryption is better.

But the question is, how do we agree a key with the server without transmitting the key for people snooping to see?

### Metaphor time

Imagine we have a secret code, and instructions for how to use the secret code. If we want to send our friend the instructions without anyone else being able to read it, what we could do is ask our friend for a lock.

Only they have the key for this lock, and we’ll assume we have an indestructible box that we can lock with it.

If we send the instructions in a locked box to our friend, they can unlock it once it reaches them and read the instructions.

After that, we can communicate in the secret code without risk of people snooping.

In this metaphor, the secret code represents a symmetric encryption key, the lock represents the server’s public key, and the key represents the server’s private key.

We’ve only used asymmetric cryptography once, so it’s fast, and we can now communicate privately with symmetric encryption.

### The Real World

In reality, we need a little more cryptography to verify the person we’re talking to is who they say they are, which is done using digital signatures and certificates.

## Digital Signatures and Certificates

### What's a Digital Signature?

Digital signatures are a way to prove the authenticity of files, to prove who created or modified them. Using asymmetric cryptography, we produce a signature with our private key and it can be verified using our public key. As only we should have access to our private key, this proves we signed the file.

The simplest form of digital signature would be encrypting the document with our private key, and then if someone wanted to verify this signature they would decrypt it with our public key and check if the files match.

### Certificates - Prove who we are!

Certificates are also a key use of public key cryptography, linked to digital signatures. A common place where they’re used is for HTTPS.

The certificates have a chain of trust, starting with a root CA (certificate authority). Root CAs are automatically trusted by our device, OS, or browser from install. Certs below that are trusted because the Root CAs say they trust that organisation. Certificates below that are trusted because the organisation is trusted by the Root CA and so on. There are long chains of trust.

## SSH Authentication

By default, SSH is authenticated using usernames and passwords in the same way that we would log in to the physical machine.

At some point, we're almost certain to hit a machine that has SSH configured with key authentication instead. This uses public and private keys to prove that the client is a valid and authorised user on the server. By default, SSH keys are RSA keys. We can choose which algorithm to generate, and/or add a passphrase to encrypt the SSH key.

### SSH Private Keys

We should treat our private SSH keys like passwords. Don’t share them, they’re called private keys for a reason. If someone has our private key, they can use it to log in to servers that will accept it unless the key is encrypted.

It’s very important to mention that the passphrase to decrypt the key isn’t used to identify us to the server at all, all it does is decrypt the SSH key. The passphrase is never transmitted, and never leaves our system.

Using tools like John the Ripper, we can attack an encrypted SSH key to attempt to find the passphrase, which highlights the importance of using a secure passphrase and keeping our private key private.

When generating an SSH key to log in to a remote machine, we should generate the keys on our machine and then copy the public key over as this means the private key never exists on the target machine. For temporary keys generated for access to CTF boxes, this doesn't matter as much.

### How do we use these keys?

The `~/.ssh` folder is the default place to store these keys for **OpenSSH**. The `authorized_keys` file in this directory holds public keys that are allowed to access the server if key authentication is enabled. By default on many distros, key authentication is enabled as it is more secure than using a password to authenticate. Normally for the root user, only key authentication is enabled.

In order to use a private SSH key, the permissions must be set up correctly otherwise our SSH client will ignore the file with a warning. Only the owner should be able to read or write to the private key.

### Using SSH keys to get a better shell

SSH keys are an excellent way to *"upgrade"* a reverse shell, assuming the user has login enabled. Leaving an SSH key in `authorized_keys` on a box can be a useful backdoor, and we don't need to deal with any of the issues of unstabilised reverse shells.

## Explaining Diffie Hellman Key Exchange

Key exchange allows 2 people/parties to establish a set of common cryptographic keys without an observer being able to get these keys. Generally, to establish common symmetric keys.

### How does Diffie Hellman Key Exchange work?

Alice and Bob want to talk securely. They want to establish a common key, so they can use symmetric cryptography, but they don’t want to use key exchange with asymmetric cryptography. This is where DH Key Exchange comes in.

Alice and Bob both have secrets that they generate, let’s call these A and B. They also have some common material that’s public, let’s call this C.

We need to make some assumptions. Firstly, whenever we combine secrets/material it’s impossible or very very difficult to separate. Secondly, the order that they're combined in doesn’t matter.

Alice and Bob will combine their secrets with the common material, and form AC and BC. They will then send these to each other, and combine that with their secrets to form two identical keys, both ABC. Now they can use this key to communicate.

DH Key Exchange is often used alongside RSA public key cryptography, to prove the identity of the person we're talking to with digital signing. This prevents someone from attacking the connection with a man-in-the-middle attack by pretending to be Bob.

## PGP, GPG and AES

### What is PGP?

**PGP** stands for **Pretty Good Privacy**. It’s a software that implements encryption for encrypting files, performing digital signing and more.

### What is GPG?

**GPG** is an Open Source implementation of PGP from the GNU project. We may need to use GPG to decrypt files in CTFs. With PGP/GPG, private keys can be protected with passphrases in a similar way to SSH private keys. If the key is passphrase protected, we can attempt to crack this passphrase using John The Ripper and `gpg2john`.

### What is AES?

**AES**, sometimes called Rijndael after its creators, stands for **Advanced Encryption Standard**. It was a replacement for DES which had short keys and other cryptographic flaws.

AES and DES both operate on blocks of data (a block is a fixed size series of bits).

## The Future - Quantum Computers and Encryption

Quantum computers will soon be a problem for many types of encryption.

### Asymmetric and Quantum

While it’s unlikely we’ll have sufficiently powerful quantum computers until around 2030, once these exist encryption that uses RSA or Elliptical Curve Cryptography will be very fast to break. This is because quantum computers can very efficiently solve the mathematical problems that these algorithms rely on for their strength.

### AES/DES and Quantum

AES with 128 bit keys is also likely to be broken by quantum computers in the near future, but 256 bit AES can’t be broken as easily. Triple DES is also vulnerable to attacks from quantum computers.

### Current Recommendations

The NSA recommends using RSA-3072 or better for asymmetric encryption and AES-256 or better for symmetric encryption. There are several competitions currently running for quantum safe cryptographic algorithms, and it’s likely that we will have a new encryption standard before quantum computers become a threat to RSA and AES.