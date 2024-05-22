# Reversing ELF

## Task 2 - Crackme2

* Category: Reverse Engineering
* Difficulty: **Easy**

### Challenge

We received a binary file named `crackme2`. Let's try to run the binary.

![](run-failed.png)

The binary is asking for a password. We need to extract the password from the binary. Let's try using `strings`.

![](password-found.png)

Seems like we found the password. Let's try running the binary again.

![](flag.png)

And we got the flag! Let's move on to the next task.