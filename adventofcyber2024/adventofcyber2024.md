# Advent of Cyber 2024

## Description

Dive into the wonderful world of cyber security by engaging in festive beginner-friendly exercises every day in the lead-up to Christmas!
* Difficulty: Easy
* Category: Advent of Cyber

## [OPSEC] Day 1: Maybe SOC-mas music, he thought, doesn't come from a store?

### The Story

*McSkidy tapped keys with a confident grin,  
A suspicious website, now where to begin?  
She'd seen sites like this, full of code and of grime,  
Shady domains, and breadcrumbs easy to find.*

McSkidy's fingers flew across the keyboard, her eyes narrowing at the suspicious website on her screen. She had seen dozens of malware campaigns like this. This time, the trail led straight to someone who went by the name "Glitch."

"Too easy," she muttered with a smirk.

"I still have time," she said, leaning closer to the screen. "Maybe there's more."

Little did she know, beneath the surface lay something far more complex than a simple hacker's handle. This was just the beginning of a tangled web unravelling everything she thought she knew.

### Learning Objectives

* Learn how to investigate malicious link files
* Learn about OPSEC and OPSEC mistakes
* Understand how to track and attribute digital identities in cyber investigations

### Challenge

#### Investigating the Website

We are given an IP address. Let's check it out.

![](day_1-webiste.png)

The website we are investigating is a Youtube to MP3 converter currently being shared amongst the organizers of SOC-mas. We've decided to dig deeper after hearing some concerning reports about this website.

At first glance, the website looks legit and presentable. The About Page even says that it was made by "The Glitch". How considerate of them to make our job easier!

Scrolling down, we'll see the feature list, which promises to be "Secure" and "Safe." From our experience, that isn't very likely.

#### Youtube to MP3 Converter Websites

These websites have been around for a long time. They offer a convenient way to extract audio from YouTube videos, making them popular. However, historically, these websites have been observed to have significant risks, such as:
* **Malvertising:** Many sites contain malicious ads that can exploit vulnerabilities in a user's system, which could lead to infection.
* **Phishing scams:** Users can be tricked into providing personal or sensitive information via fake surveys or offers.
* **Bundled malware:** Some converters may come with malware, tricking users into unknowingly running it.

#### Getting some tunes

Let's find out by pasting a Youtube link into the converter. This should download a file for us to investigate. We will be using [our anthem song](https://www.youtube.com/watch?v=dQw4w9WgXcQ) for this. We then extract the downloaded file.

![](day_1-file-extraction.png)

We can see that there are 2 files extracted: `song.mp3` and `somg.mp3`.

Let's quickly determine the file type of these files using the `file` command.

![](day_1-file-types.png)

The `song.mp3` file is a regular audio file, while the `somg.mp3` file is an MS Windows shortcut file, aka a `.lnk` file. This file type is used in Windows to link to another file, folder, or application. These shortcuts can also be used to run commands!

There are multiple ways to inspect a `.lnk` file to reveal the embedded commands and attributes. This time we will be using `exiftool`.

![](day_1-exiftool.png)

Let's go through details of the command shown in the output:
* The `-ep Bypass -nop` flags disable PowerShell's usual restrictions, allowing the script to run without interference from security settings or user profiles.
* The `DownloadFile` method pulls an `IS.ps1` file from a remote `https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1` server and saves it in the `C:\ProgramData` directory.
* Once downloaded, the script is executed using the `iex` command, stands for `Invoke-Expression`, which triggers the downloaded `s.ps1` script.

Now we know what the link file does. Let's take a look at the script it downloads. We can visit the link in the command to view the script.

![](day_1-script.png)

We can see that the script is designed to collect sensitive information from the victim's system, such as cryptocurrency wallets and saved browser credentials, and then send it to an attacker's remote server.

This looks fairly typical of a PowerShell script for such a purpose, with one notable exception: a signature in the code that reads `Created by the one and only M.M.`.

#### Searching the Source

There are many paths we could take to continue our investigation. We could investigate the website further, analyse its source code, or search for open directories that might reveal more information about the malicious actor's setup. We can search for the hash or signature on public malware databases like VirusTotal or AnyRun. Each of these methods could yield useful clues.

However, we will try something different this time. Since we already have the PowerShell code, searching for it online might give us useful leads. It's a long shot, but we'll explore it in this exercise.

There are many places where we can search for code. The most widely used is Github. So let's try searching there.

To search effectively, we can look for unique parts of the code that we could use to search with. The more distinctive, the better. For this scenario, we have the string we've uncovered before that reads: `Created by the one and only M.M.`.

![](day_1-search-result.png)

As we go through the search result, we found an interesting issue thread. Let's take a look at it.

![](day_1-github-issue.png)

Looks like this user has made a critical mistake.

##### Introduction to OPSEC

This is a classic case of OPSEC failure.

Operational Security (OPSEC) is a term originally coined in the military to refer to the process of protecting sensitive information and operations from adversaries. The goal is to identify and eliminate potential vulnerabilities before the attacker can learn their identity.

In the context of cyber security, when malicious actors fail to follow proper OPSEC practices, they might leave digital traces that can be pieced together to reveal their identity. Some common OPSEC mistakes include:
* Reusing usernames, email addresses, or account handles across multiple platforms. One might assume that anyone trying to cover their tracks would remove such obvious and incriminating information, but sometimes, it's due to vanity or simply forgetfulness.
* Using identifiable metadata in code, documents, or images, which may reveal personal information like device names, GPS coordinates, or timestamps.
* Posting publicly on forums or GitHub with details that tie back to their real identity or reveal their location or habits.
* Failing to use a VPN or proxy while conducting malicious activities allows law enforcement to track their real IP address.

We'd think that someone doing something bad would make OPSEC their top priority, but they're only human and can make mistakes, too.

Here are some real-world OPSEC mistakes that led to some really big fails:

##### AlphaBay Admin Takedown

One of the most spectacular OPSEC failures involved Alexandre Cazes, the administrator of AlphaBay, one of the largest dark web marketplaces:
* Cazes used the email address `pimp_alex_91@hotmail.com` in early welcome emails from the site.
* This email included his year of birth and other identifying information.
* He cashed out using a Bitcoin account tied to his real name.
* Cazes reused the username `Alpha02` across multiple platforms, linking his dark web identity to forum posts under his real name.

##### Chinese Military Hacking Group (APT1)

There's also the notorious Chinese hacking group APT1, which made several OPSEC blunders:
* One member, Wang Dong, signed his malware code with the nickname `Ugly Gorilla`.
* This nickname was linked to programming forum posts associated with his real name.
* The group used predictable naming conventions for users, code, and passwords.
* Their activity consistently aligned with Beijing business hours, making their location obvious.

These failures provided enough information for cyber security researchers and law enforcement to publicly identify group members.

#### Uncovering MM

We know the attacker left a distinctive signature in the PowerShell code (MM). This allowed us to search for related repositories and issues pages on GitHub. We then discovered an Issues page where the attacker engaged in discussions, providing more context and linking their activity to other projects.

In this discussion, they responded to a query about modifying the code. This response, paired with their unique handle, was another critical slip-up, leaving behind a trail of evidence that can be traced back to them. By analysing the timestamps, usernames, and the nature of their interactions, we can now attribute the mastermind behind the attack to MM.

#### What's Next?

*McSkidy dug deeper, her mind sharp and quick,  
But something felt off, a peculiar trick.  
The pieces she’d gathered just didn’t align,  
A puzzle with gaps, a tangled design.*

As McSkidy continued digging, a pattern emerged that didn't fit the persona she was piecing together. A different handle appeared in obscure places, buried deep in the details: `MM.`

"Who's MM?" McSkidy muttered, the mystery deepening.

Even though all signs on the website seemed to point to Glitch as the author, it became clear that someone had gone to great lengths to ensure Glitch's name appeared everywhere. Yet, the scattered traces left by MM suggested a deliberate effort to shift the blame.

#### Solving challenge questions

1. Who is the author of the song?

As we check the `song.mp3` file with `exiftool`, we can see the name of the author in the metadata.

```
┌──(DrunkenHacker㉿kali)-[~/MyCourses/TryHackMe/adventofcyber2024/Day1]
└─$ exiftool song.mp3 
ExifTool Version Number         : 12.76
File Name                       : song.mp3
Directory                       : .
File Size                       : 4.6 MB
File Modification Date/Time     : 2024:10:24 09:50:46+02:00
File Access Date/Time           : 2024:12:02 13:06:58+01:00
File Inode Change Date/Time     : 2024:12:02 12:57:46+01:00
File Permissions                : -rwxrwxr-x
File Type                       : MP3
File Type Extension             : mp3
MIME Type                       : audio/mpeg
MPEG Audio Version              : 1
Audio Layer                     : 3
Audio Bitrate                   : 192 kbps
Sample Rate                     : 44100
Channel Mode                    : Stereo
MS Stereo                       : Off
Intensity Stereo                : Off
Copyright Flag                  : False
Original Media                  : False
Emphasis                        : None
ID3 Size                        : 2176
Artist                          : [REDACTED]
Album                           : Rap
Title                           : Mount HackIt
Encoded By                      : Mixcraft 10.5 Recording Studio Build 621
Year                            : 2024
Genre                           : Rock
Track                           : 0/1
Comment                         : 
Date/Time Original              : 2024
Duration                        : 0:03:11 (approx)
```

2. The malicious PowerShell script sends stolen info to a C2 server. What is the URL of this C2 server?

We have seen the URL in the PowerShell script.

3. Who is M.M? Maybe his Github profile page would provide clues?

As we go to the Github profile page of `MM-WarevilleTHM`, we can see 2 public repositories: `IS` and `M.M`. The `IS` repository contains the PowerShell script we have seen before. As we check the other repository, we can see that it contains a Markdown file as follows:

```markdown
- Hi, I’m M.M, also known as [REDACTED]. I run things in Wareville Town.
- This year, SOC-mas is not going to happen and I will do all I can to sabotage it.
- I'll develop all necessary tools and plans to sabotage the event and frustrate the citizens of Wareville. One thing is to find someone to blame for all this. Maybe Glitch will take the blame.
- How to reach me? Find me around Wareville.
```

4. What is the number of commits on the GitHub repo where the issue was raised?

We can go the issue thread we found earlier, then go to **Insights** $\rightarrow$ **Commits** to see the number of commits.