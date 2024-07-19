# Walking An Application

## Description

Manually review a web application for security issues using only your browsers developer tools. Hacking with just your browser, no tools or scripts.
* Category: Walkthrough

## Walking An Application

In this room we will learn how to manually review a web application for security issues using only the in-built tools in our browser. More often than not, automated security tools and scripts will miss many potential vulnerabilities and useful information.

## Exploring The Website

As a penetration tester, our role when reviewing a website or web application is to discover features that could potentially be vulnerable and attempt to exploit them to assess whether or not they are. These features are usually parts of the website that require some interactivity with the user.

Finding interactive portions of the website can be as easy as spotting a login form to manually reviewing the website's JavaScript. An excellent place to start is just with our browser exploring the website and noting down the individual pages/areas/features with a summary for each one.

## Viewing The Page Source

The page source is the human-readable code returned to our browser/client from the web server each time we make a request.

The returned code is made up of **HTML (HyperText Markup Language)**, **CSS (Cascading Style Sheets)** and **JavaScript**, and it's what tells our browser what content to display, how to show it and adds an element of interactivity with JavaScript.

Viewing the page source can help us discover more information about the web application.

## Developer Tools - Inspector

Every modern browser includes developer tools. This is a tool kit used to aid web developers in debugging web applications and gives us a peek under the hood of a website to see what is going on.

As a pentester, we can leverage these tools to provide us with a much better understanding of the web application. We're specifically focusing on three features of the developer tool kit, Inspector, Debugger and Network.

### Inspector

The page source doesn't always represent what's shown on a webpage. This is because CSS, JavaScript and user interaction can change the content and style of the page, which means we need a way to view what's been displayed in the browser window at this exact time. Element inspector assists us with this by providing us with a live representation of what is currently on the website.

As well as viewing this live view, we can also edit and interact with the page elements, which is helpful for web developers to debug issues.

## Developer Tools - Debugger

This panel in the developer tools is intended for debugging JavaScript, and is an excellent feature for web developers wanting to work out why something might not be working.

As penetration testers, it gives us the option of digging deep into the JavaScript code. In Firefox and Safari, this feature is called Debugger, but in Google Chrome, it's called Sources.

## Developer Tools - Network

The network tab on the developer tools can be used to keep track of every external request a webpage makes. If we click on the Network tab and then refresh the page, we'll see all the files the page is requesting.