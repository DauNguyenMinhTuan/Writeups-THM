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

