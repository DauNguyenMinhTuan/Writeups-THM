# IDOR

## Description

Learn how to find and exploit IDOR vulnerabilities in a web application giving you access to data that we shouldn't have.
* Category: Walkthrough

## What is an IDOR?

IDOR stands for Insecure Direct Object Reference and is a type of access control vulnerability.

This type of vulnerability can occur when a web server receives user-supplied input to retrieve objects, too much trust has been placed on the input data, and it is not validated on the server-side to confirm the requested object belongs to the user requesting it.

## Finding IDORs in Encoded IDs

When passing data from page to page either by post data, query strings, or cookies, web developers will often first take the raw data and encode it. Encoding ensures that the receiving web server will be able to understand the contents. Encoding changes binary data into an ASCII string commonly using the `a-z, A-Z, 0-9 and =` character for padding.

The most common encoding technique on the web is base64 encoding and can usually be pretty easy to spot. We can use websites like `https://www.base64decode.org/` to decode the string, then edit the data and re-encode it again using `https://www.base64encode.org/` and then resubmit the web request to see if there is a change in the response.

## Finding IDORs in Hashed IDs

Hashed IDs are a little bit more complicated to deal with than encoded ones, but they may follow a predictable pattern, such as being the hashed version of the integer value.

It's worthwhile putting any discovered hashes through a web service such as `https://crackstation.net/` (which has a database of billions of hash to value results) to see if we can find any matches.

## Finding IDORs in Unpredictable IDs

If the Id cannot be detected using the above methods, an excellent method of IDOR detection is to create two accounts and swap the Id numbers between them. If we can view the other users' content using their Id number while still being logged in with a different account (or not logged in at all), we've found a valid IDOR vulnerability.

## Where are IDORs located

The vulnerable endpoint we're targeting may not always be something we see in the address bar. It could be content our browser loads in via an AJAX request or something that we find referenced in a JavaScript file.

Sometimes endpoints could have an unreferenced parameter that may have been of some use during development and got pushed to production. For example, we may notice a call to `/user/details` displaying our user information (authenticated through our session). But through an attack known as parameter mining, we discover a parameter called `user_id` that we can use to display other users' information, for example, `/user/details?user_id=123`.