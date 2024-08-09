# Phishing

## Description

Learn what phishing is and why it's important to a red team engagement. You will set up phishing infrastructure, write a convincing phishing email and try to trick your target into opening your email in a real-world simulation. 
* Category: Walkthrough

## Intro to Phishing Attacks

Social engineering is the psychological manipulation of people into performing or divulging information by exploiting weaknesses in human nature. These "weaknesses" can be curiosity, jealously, greed and even kindness and the willingness to help someone. Phishing is a source of social engineering delivered through email to trick someone into either revealing personal information, credentials or even executing malicious code on their computer.

These emails will usually appear to come from a trusted source, whether that's a person or a business. They include content that tries to tempt or trick people into downloading software, opening attachments, or following links to a bogus website.

The type of phishing campaign a red team would participate in is **spear-phishing**. As with throwing a physical spear, in spear-phishing we'd have a target to aim at. This is an effective form of phishing for a red team engagement as they are bespoke to the target it makes them hard to detect by technology such as spam filters, antivirus and firewalls.

A red team could be contracted to solely carry out a phishing assessment to see whether a business is vulnerable to this type of attack or can also be part of a broader scale assessment and used to gain access to computer systems or services.

Some other methods of phishing through other mediums are smishing which is phishing through SMS messages, and vishing which is performed through phone calls.

## Writing Convincing Phishing Emails

We have 3 things to work with regarding phishing emails: the sender's email address, the subject and the content.

### The sender address

Ideally, the sender's address would be from a domain name that spoofs a significant brand, a known contact, or a coworker.

To find what brands or people a victim interacts with, we can employ OSINT (Open Source Intelligence) tactics. For example:
* Observe their social media account for any brands or friends they talk to.
* Searching Google for the victim's name and rough location for any reviews the victim may have left about local businesses or brands.
* Looking at the victim's business website to find suppliers.
* Looking at LinkedIn to find coworkers of the victim.

### The subject

We should set the subject to something quite urgent, worrying or piques the victim's curiosity, so they do not ignore it and act on it quickly.

Examples of this could be:
* Your account has been compromised!
* Your package has been dispatched/shipped.
* Staff payroll information (do not forward!).
* Your photos have been published.

### The content

If impersonating a brand or supplier, it would be pertinent to research their standard email templates and branding (style, logo's images, signoffs etc.) and make our content look the same as theirs, so the victim doesn't expect anything.

If impersonating a contact or coworker, it could be beneficial to contact them; first, they may have some branding in their template, have a particular email signature or even something small such as how they refer to themselves. Learning these somewhat small things can sometimes have quite dramatic psychological effects on the victim and convince them more to open and act on the email.

If we've set up a spoof website to harvest data or distribute malware, the links to this should be disguised using the anchor text and changing it either to some text which says "Click Here" or changing it to a correct looking link that reflects the business we are spoofing, for example:
* `<a href="http://spoofsite.com">Click Here</a>`
* `<a href="http://spoofsite.com">https://onlinebank.com</a>`

## Phishing Infrastructure

A certain amount of infrastructure will need to be put in place to launch a successful phishing campaign.

#### Domain name

We'll need to register either an authentic-looking domain name or one that mimics the identity of another domain.

#### SSL/TLS certificate

Creating SSL/TLS certificates for our chosen domain name will add an extra layer of authenticity to the attack.

#### Email Server/Account

We'll need to either set up an email server or register with an SMTP service provider.

#### DNS Records

Setting up DNS records such as SPF, DKIM, DMARC will improve the deliverability of our emails and make sure they're getting into the inbox rather than the spam folder.

#### Web Server

We'll need to set up webservers or purchase web hosting from a company to host our phishing website. Adding SSL/TLS to the website will give them an extra layer of authenticity.

#### Analytics

When a phishing campaign is part of a red team engagement, keeping analytics information is more important. We'll need something to keep track of the emails that have been sent, opened or clicked. We'll also need to combine it with information from our phishing website for which users have supplied personal information or downloaded malware.

### Automation and Useful Software

Some of the above infrastructure can be quickly automated be using the below tools

#### GoPhish - (Open-Source Phishing Framework) - getgophish.com

GoPhish is a web-based framework to make setting up phishing campaigns more straightforward. GoPhish allows us to store our SMTP server settings for sending emails, has a web-based tool for creating email templates using a simple *WYSIWYG (What You See Is What You Get)* editor. We can also schedule when emails are sent and have an analytics dashboard that shows how many emails have been sent, opened or clicked.

#### SET - (Social Engineering Toolkit) - trustedsec.com

The Social Engineering Toolkit contains a multitude of tools, but some of the important ones for phishing are the ability to create spear-phishing attacks and deploy fake versions of common websites to trick victims into entering their credentials.

## Droppers

Droppers are software that phishing victims tend to be tricked into downloading and running on their system. The dropper may advertise itself as something useful or legitimate such as a codec to view a certain video or software to open a specific file.

The droppers are not usually malicious themselves, so they tend to pass antivirus checks. Once installed, the intended malware is either unpacked or downloaded from a server and installed onto the victim's computer. The malicious software usually connects back to the attacker's infrastructure. The attacker can take control of the victim's computer, which can further explore and exploit the local network.

## Choosing a phishing domain

Choosing the right phishing domain to launch our attack is essential to ensure we have the psychological edge over the target. A red team engagement can use some of the below methods for choosing the perfect domain name.

### Expired Domains

Although not essential, buying a domain name with some history may lead to better scoring of our domain when it comes to spam filters. Spam filters have a tendency to not trust brand new domain names compared to ones with some history.

### Typosquatting

Typosquatting is when a registered domain looks very similar to the target domain we're trying to impersonate.

Here are some common methods:
* **Misspelling:** `goggle.com` Vs `google.com`
* **Additional period:** `go.ogle.com` Vs `google.com`
* **Switching numbers for letters:** `g00gle.com` Vs `google.com`
* **Phrasing:** `googles.com` Vs `google.com`
* **Additional Words:** `googleresults.com` Vs `google.com`

These changes might look unrealistic, but at a glance, the human brain tends to fill in the blanks and see what it wants to see, i.e. the correct domain name.

### TLD Alternatives

A common trick for choosing a domain would be to use the same name but with a different TLD. For example, register `tryhackme.co.uk` to impersonate `tryhackme.com`.

### IDN Homograph Attack / Script Spoofing

Originally domain names were made up of Latin characters a-z and 0-9, but in 1998, IDN (internationalized domain name) was implemented to support language-specific script or alphabet from other languages such as Arabic, Chinese, Cyrillic, Hebrew and more. An issue that arises from the IDN implementation is that different letters from different languages can actually appear identical. For example, Unicode character U+0430 (Cyrillic small letter a) looks identical to Unicode character U+0061 (Latin small letter a) used in English, enabling attackers to register a domain name that looks almost identical to another.

## Using MS Office in Phishing

Often during phishing campaigns, a Microsoft Office document (typically Word, Excel or PowerPoint) will be included as an attachment. Office documents can contain macros; macros do have a legitimate use but can also be used to run computer commands that can cause malware to be installed onto the victim's computer or connect back to an attacker's network and allow the attacker to take control of the victim's computer.

## Using Browser Exploits

Another method of gaining control over a victim's computer could be through browser exploits; this is when there is a vulnerability against a browser itself (Internet Explorer/Edge, Firefox, Chrome, Safari, etc.), which allows the attacker to run remote commands on the victim's computer.

Browser exploits aren't usually a common path to follow in a red team engagement unless we have prior knowledge of old technology being used on-site. Many browsers are kept up to date, hard to exploit due to how browsers are developed, and the exploits are often worth a lot of money if reported back to the developers.

That being said, it can happen, and as previously mentioned, it could be used to target old technologies on-site because possibly the browser software cannot be updated due to incompatibility with commercial software/hardware, which can happen quite often in big institutions such as education, government and especially health care.

Usually, the victim would receive an email, convincing them to visit a particular website set up by the attacker. Once the victim is on the site, the exploit works against the browser, and now the attacker can perform any commands they wish on the victim's computer.