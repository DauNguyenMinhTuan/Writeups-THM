# Intro to SSRF

## Description

Learn how to exploit Server-Side Request Forgery (SSRF) vulnerabilities, allowing us to access internal server resources.
* Category: Walkthrough

## What is an SSRF?

SSRF stands for Server-Side Request Forgery. It's a vulnerability that allows a malicious user to cause the webserver to make an additional or edited HTTP request to the resource of the attacker's choosing.

### Types of SSRF

There are two types of SSRF vulnerability. The first is a regular SSRF where data is returned to the attacker's screen. The second is a Blind SSRF vulnerability where an SSRF occurs, but no information is returned to the attacker's screen.

### What's the impact?

A successful SSRF attack can result in any of the following:
* Access to unauthorised areas.
* Access to customer/organisational data.
* Ability to Scale to internal networks.
* Reveal authentication tokens/credentials.

## Finding an SSRF

Potential SSRF vulnerabilities can be spotted in web applications in many different ways. Here is an example of four common places to look:
1. When a full URL is used in a parameter in the address bar.
2. A hidden field in a form.
3. A partial URL such as just the hostname.
4. The path of the URL

Some of these examples are easier to exploit than others, and this is where a lot of trial and error will be required to find a working payload.

If working with a blind SSRF where no output is reflected back to us, we'll need to use an external HTTP logging tool to monitor requests such as `requestbin.com`, our own HTTP server or Burp Suite's Collaborator client.

## Defeating Common SSRF Defences

More security-savvy developers aware of the risks of SSRF vulnerabilities may implement checks in their applications to make sure the requested resource meets specific rules. There are usually two approaches to this, either a deny list or an allow list.

### Deny List

A Deny List is where all requests are accepted apart from resources specified in a list or matching a particular pattern.

A Web Application may employ a deny list to protect sensitive endpoints, IP addresses or domains from being accessed by the public while still allowing access to other locations. A specific endpoint to restrict access is the `localhost`, which may contain server performance data or further sensitive information, so domain names such as `localhost` and `127.0.0.1` would appear on a deny list.

Attackers can bypass a Deny List by using alternative localhost references such as `0`, `0.0.0.0`, `0000`, `127.1`, `127.*.*.*`, `2130706433`, `017700000001` or subdomains that have a DNS record which resolves to the IP Address `127.0.0.1` such as `127.0.0.1.nip.io.`

Also, in a cloud environment, it would be beneficial to block access to the IP address `169.254.169.254`, which contains metadata for the deployed cloud server, including possibly sensitive information. An attacker can bypass this by registering a subdomain on their own domain with a DNS record that points to the IP Address `169.254.169.254`.

### Allow List

An allow list is where all requests get denied unless they appear on a list or match a particular pattern, such as a rule about what an URL used in a parameter must begin with.

An attacker could quickly circumvent this rule by creating a subdomain on an attacker's domain name. The application logic would now allow this input and let an attacker control the internal HTTP request.

### Open Redirect

If the above bypasses do not work, there is one more trick up the attacker's sleeve, the open redirect. An open redirect is an endpoint on the server where the website visitor gets automatically redirected to another website address.