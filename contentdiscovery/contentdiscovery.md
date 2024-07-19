# Content Discovery

## Description

Learn the various ways of discovering hidden or private content on a webserver that could lead to new vulnerabilities.
* Category: Walkthrough

## What is Content Discovery?

Content can be many things, a file, video, picture, backup, a website feature. When we talk about content discovery, we're not talking about the obvious things we can see on a website. It's the things that aren't immediately presented to us and that weren't always intended for public access.

This content could be, for example, pages or portals intended for staff usage, older versions of the website, backup files, configuration files, administration panels, etc.

There are three main ways of discovering content on a website which we'll cover. Manually, Automated and OSINT (Open-Source Intelligence).

## Manual Discovery - Robots.txt

There are multiple places we can manually check on a website to start discovering more content.

### Robots.txt

The robots.txt file is a document that tells search engines which pages they are and aren't allowed to show on their search engine results or ban specific search engines from crawling the website altogether.

It can be common practice to restrict certain website areas so they aren't displayed in search engine results. These pages may be areas such as administration portals or files meant for the website's customers. This file gives us a great list of locations on the website that the owners don't want us to discover as penetration testers.

## Manual Discovery - Favicon

The favicon is a small icon displayed in the browser's address bar or tab used for branding a website.

Sometimes when frameworks are used to build a website, a favicon that is part of the installation gets leftover, and if the website developer doesn't replace this with a custom one, this can give us a clue on what framework is in use.

OWASP host a [database](https://wiki.owasp.org/index.php/OWASP_favicon_database) of common framework icons that we can use to check against the targets favicon. Once we know the framework stack, we can use external resources to discover more about it.

## Manual Discovery - Sitemap.xml

Unlike the robots.txt file, which restricts what search engine crawlers can look at, the sitemap.xml file gives a list of every file the website owner wishes to be listed on a search engine. These can sometimes contain areas of the website that are a bit more difficult to navigate to or even list some old webpages that the current site no longer uses but are still working behind the scenes.

## Manual Discovery - HTTP Headers

When we make requests to the web server, the server returns various HTTP headers. These headers can sometimes contain useful information such as the webserver software and possibly the programming/scripting language in use. Using this information, we could find vulnerable versions of software being used.

## Manual Discovery - Framework Stack

Once we've established the framework of a website, either from the above favicon example or by looking for clues in the page source such as comments, copyright notices or credits, we can then locate the framework's website. From there, we can learn more about the software and other information, possibly leading to more content we can discover.

## OSINT - Google Hacking/Dorking

There are also external resources available that can help in discovering information about our target website. These resources are often referred to as OSINT (Open-Source Intelligence) as they're freely available tools that collect information.

### Google Hacking/Dorking

Google Hacking / Dorking utilizes Google's advanced search engine features, which allow us to pick out custom content. We can, for instance, pick out results from a certain domain name using the `site:` filter, for example (site:tryhackme.com). We can then match this up with certain search terms, say, for example, the word admin (site:tryhackme.com admin) this then would only return results from the tryhackme.com website which contain the word admin in its content. We can combine multiple filters as well.

Here is an example of more filters we can use:
| **Filter** | **Example** | **Description** |
| - | - | - |
| `site:` | `site:tryhackme.com` | returns results only from the specified website address |
| `inurl:` | `inurl:admin` | returns results that have the specified word in the URL |
| `filetype:` | `filetype:pdf` | returns results which are a particular file extension |
| `intitle:` | `intitle:admin` | returns results that contain the specified word in the title |

## OSINT - Wappalyzer

**Wappalyzer** is an online tool and browser extension that helps identify what technologies a website uses, such as frameworks, Content Management Systems (CMS), payment processors and much more, and it can even find version numbers as well.

## OSINT - Wayback Machine

The **Wayback Machine** is a historical archive of websites that dates back to the late 90s. We can search a domain name, and it will show us all the times the service scraped the web page and saved the contents. This service can help uncover old pages that may still be active on the current website.

## OSINT - GitHub

To understand GitHub, we first need to understand Git. Git is a version control system that tracks changes to files in a project. Working in a team is easier because we can see what each team member is editing and what changes they made to files. When users have finished making their changes, they commit them with a message and then push them back to a central location (repository) for the other users to then pull those changes to their local machines.

GitHub is a hosted version of Git on the internet. Repositories can either be set to public or private and have various access controls. We can use GitHub's search feature to look for company names or website names to try and locate repositories belonging to our target. Once discovered, we may have access to source code, passwords or other content that we hadn't yet found.

## OSINT - S3 Buckets

S3 Buckets are a storage service provided by Amazon AWS, allowing people to save files and even static website content in the cloud accessible over HTTP and HTTPS. The owner of the files can set access permissions to either make files public, private and even writable. Sometimes these access permissions are incorrectly set and inadvertently allow access to files that shouldn't be available to the public.

The format of the S3 buckets is `http(s)://{name}.s3.amazonaws.com` where `{name}` is decided by the owner, such as `tryhackme-assets.s3.amazonaws.com`. S3 buckets can be discovered in many ways, such as finding the URLs in the website's page source, GitHub repositories, or even automating the process. One common automation method is by using the company name followed by common terms such as `{name}-assets`, `{name}-www`, `{name}-public`, `{name}-private`, etc.

## Automated Discovery

Automated discovery is the process of using tools to discover content rather than doing it manually. This process is automated as it usually contains hundreds, thousands or even millions of requests to a web server. These requests check whether a file or directory exists on a website, giving us access to resources we didn't previously know existed. This process is made possible by using a resource called wordlists.

### What are wordlists?

Wordlists are just text files that contain a long list of commonly used words. They can cover many different use cases. An excellent resource for wordlists is [SecLists](https://github.com/danielmiessler/SecLists) which **Daniel Miessler** curates.

### Automation tools

Although there are many different content discovery tools available, all with their features and flaws, some of the most popular tools are: `ffuf`, `dirb` and `gobuster`.