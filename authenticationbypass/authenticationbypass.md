# Authentication Bypass

## Description

Learn how to defeat logins and other authentication mechanisms to allow us access to unpermitted areas.
* Category: Walkthrough

## Brief

In this room, we will learn about different ways website authentication methods can be bypassed, defeated or broken. These vulnerabilities can be some of the most critical as it often ends in leaks of customers personal data.

## Username Enumeration

A helpful exercise to complete when trying to find authentication vulnerabilities is creating a list of valid usernames, which we'll use later in other tasks.

Website error messages are great resources for collating this information to build our list of valid usernames.

## Brute Force

A brute force attack is an automated process that tries a list of commonly used passwords against either a single username or a list of usernames.

## Logic Flaw

Sometimes authentication processes contain logic flaws. A logic flaw is when the typical logical path of an application is either bypassed, circumvented or manipulated by a hacker.

## Cookie Tampering

Examining and editing the cookies set by the web server during our online session can have multiple outcomes, such as unauthenticated access, access to another user's account, or elevated privileges.

### Plain Text

The contents of some cookies can be in plain text, and it is obvious what they do.

### Hashing

Sometimes cookie values can look like a long string of random characters. These are called hashes which are an irreversible representation of the original text. Here are some examples:

| **Original String** | **Hash Method** | **Output** |
| - | - | - |
| 1 | md5 | c4ca4238a0b923820dcc509a6f75849b |
| 1 | sha-256 | 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b |
| 1 | sha-512 | 4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a |
| 1 | sha1 | 356a192b7913b04c54574d18c28d46e6395428ab |

The hash output from the same input string can significantly differ depending on the hash method in use. Even though the hash is irreversible, the same output is produced every time, which is helpful for us as services such as `https://crackstation.net/` keep databases of billions of hashes and their original strings.

### Encoding

Encoding is similar to hashing in that it creates what would seem to be a random string of text, but in fact, the encoding is reversible.

Encoding allows us to convert binary data into human-readable text that can be easily and safely transmitted over mediums that only support plain text ASCII characters.

Common encoding types are **base32** which converts binary data to the characters `A-Z` and `2-7`, and **base64** which converts using the characters `a-z`, `A-Z`, `0-9`, `+`, `/` and the equals sign for padding.