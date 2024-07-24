# Passive Reconnaissance

## Description

Learn about the essential tools for passive reconnaissance, such as whois, nslookup, and dig.
* Category: Walkthrough

## Introduction

We use `whois` to query WHOIS records, while we use `nslookup` and `dig` to query DNS database records. These are all publicly available records and hence do not alert the target.

We will also learn the usage of two online services:
* DNSDumpster
* Shodan.io

These two online services allow us to collect information about our target without directly connecting to it.

## Passive Versus Active Recon

Before the dawn of computer systems and networks, in the Art of War, Sun Tzu taught, "If you know the enemy and know yourself, your victory will not stand in doubt." If we are playing the role of an attacker, we need to gather information about our target systems. If we are playing the role of a defender, we need to know what our adversary will discover about our systems and networks.

Reconnaissance (recon) can be defined as a preliminary survey to gather information about a target. It is the first step in **The Unified Kill Chain** to gain an initial foothold on a system. We divide reconnaissance into:
1. Passive Reconnaissance
2. Active Reconnaissance

In passive reconnaissance, we rely on publicly available knowledge. It is the knowledge that we can access from publicly available resources without directly engaging with the target. Think of it like we are looking at target territory from afar without stepping foot on that territory.

Passive reconnaissance activities include many activities, for instance:
* Looking up DNS records of a domain from a public DNS server.
* Checking job ads related to the target website.
* Reading news articles about the target company.

Active reconnaissance, on the other hand, cannot be achieved so discreetly. It requires direct engagement with the target. Think of it like we check the locks on the doors and windows, among other potential entry points.

Examples of active reconnaissance activities include:
* Connecting to one of the company servers such as HTTP, FTP, and SMTP.
* Calling the company in an attempt to get information (social engineering).
* Entering company premises pretending to be a repairman.

Considering the invasive nature of active reconnaissance, one can quickly get into legal trouble unless one obtains proper legal authorisation.

## Whois

**WHOIS** is a request and response protocol that follows the *RFC 3912* specification. A WHOIS server listens on TCP port 43 for incoming requests. The domain registrar is responsible for maintaining the WHOIS records for the domain names it is leasing. The WHOIS server replies with various information related to the domain requested. Of particular interest, we can learn:
* Registrar: Via which registrar was the domain name registered?
* Contact info of registrant: Name, organization, address, phone, among other things. (unless made hidden via a privacy service)
* Creation, update, and expiration dates: When was the domain name first registered? When was it last updated? And when does it need to be renewed?
* Name Server: Which server to ask to resolve the domain name?

To get this information, we need to use a `whois` client or an online service. Many online services provide whois information. However, it is generally faster and more convenient to use our local `whois` client. The syntax for this is `whois DOMAIN_NAME`, where `DOMAIN_NAME` is the domain about which we are trying to get more information.

The information collected can be inspected to find new attack surfaces, such as social engineering or technical attacks. For instance, depending on the scope of the penetration test, we might consider an attack against the email server of the admin user or the DNS servers, assuming they are owned by our client and fall within the scope of the penetration test.

It is important to note that due to automated tools abusing WHOIS queries to harvest email addresses, many WHOIS services take measures against this. They might redact email addresses, for instance. Moreover, many registrants subscribe to privacy services to avoid their email addresses being harvested by spammers and keep their information private.

## nslookup and dig

We can find the IP address of a domain name using `nslookup`, which stands for *Name Server Look Up*. We need to issue the command `nslookup DOMAIN_NAME`. Or, more generally, we can use `nslookup OPTIONS DOMAIN_NAME SERVER`. These three main parameters are:
* `OPTIONS` contains the query type as shown in the table below.
* `DOMAIN_NAME` is the domain name we are looking up.
* `SERVER` is the DNS server that we want to query. We can choose any local or public DNS server to query. **Cloudflare** offers `1.1.1.1` and `1.0.0.1`, **Google** offers `8.8.8.8` and `8.8.4.4`, and **Quad9** offers `9.9.9.9` and `149.112.112.112`. There are many more public DNS servers that we can choose from if we want alternatives to our ISP’s DNS servers.

| **Query Type** | **Result** |
| - | - |
| A | IPv4 address |
| AAAA | IPv6 address |
| CNAME | Canonical Name |
| MX | Mail Servers |
| SOA | Start of Authority |
| TXT | TXT records |

The A and AAAA records are used to return IPv4 and IPv6 addresses, respectively. This lookup is helpful to know from a penetration testing perspective.

For more advanced DNS queries and additional functionality, we can use `dig`, the acronym for "Domain Information Groper". We can use `dig DOMAIN_NAME`, but to specify the record type, we would use `dig DOMAIN_NAME TYPE`. Optionally, we can select the server we want to query using `dig @SERVER DOMAIN_NAME TYPE`.

A quick comparison between the output of `nslookup` and `dig` shows that `dig` returned more information, such as the TTL (Time To Live) by default.

## DNSDumpster

DNS lookup tools, such as `nslookup` and `dig`, cannot find subdomains on their own. The domain we are inspecting might include a different subdomain that can reveal much information about the target. There is a possibility that one of these subdomains has been set up and is not updated regularly. Lack of proper regular updates usually leads to vulnerable services. But how can we know that such subdomains exist?

We can consider using multiple search engines to compile a list of publicly known subdomains. One search engine won’t be enough. Moreover, we should expect to go through at least tens of results to find interesting data. After all, we are looking for subdomains that are not explicitly advertised, and hence it is not necessary to make it to the first page of search results. Another approach to discover such subdomains would be to rely on brute-forcing queries to find which subdomains have DNS records.

To avoid such a time-consuming search, one can use an online service that offers detailed answers to DNS queries, such as **DNSDumpster**. In addition, DNSDumpster will return the collected DNS information in easy-to-read tables and a graph. DNSDumpster will also provide any collected information about listening servers.

DNSDumpster will also represent the collected information graphically. DNSDumpster displayed the data from the table earlier as a graph.

## Shodan.io

When we are tasked to run a penetration test against specific targets, as part of the passive reconnaissance phase, a service like **Shodan.io** can be helpful to learn various pieces of information about the client’s network, without actively connecting to it.

Furthermore, on the defensive side, we can use different services from Shodan.io to learn about connected and exposed devices belonging to our organization.

Shodan.io tries to connect to every device reachable online to build a search engine of connected "things" in contrast with a search engine for web pages. Once it gets a response, it collects all the information related to the service and saves it in the database to make it searchable.

Via Shodan.io search result, we can learn several things related to our search, such as:
* IP address
* Hosting company
* Geographic location
* Server type and version