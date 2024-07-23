# Burp Suite: Other Modules

## Description

Take a dive into some of Burp Suite's lesser-known modules.
* Category: Walkthrough

## Introduction

In addition to the widely recognized Repeater and Intruder, Burp Suite incorporates several lesser-known modules.

The spotlight will be on the Decoder, Comparer, Sequencer, and Organizer tools. They facilitate operations with encoded text, enable comparison of data sets, allow the analysis of randomness within captured tokens, and help us store and annotate copies of HTTP messages that we may want to revisit later. Although these tasks appear straightforward, accomplishing them within Burp Suite can substantially save time, thus emphasizing the importance of learning to use these modules effectively.

## Decoder: Overview

The Decoder module of Burp Suite gives user data manipulation capabilities. As implied by its name, it not only decodes data intercepted during an attack but also provides the function to encode our own data, prepping it for transmission to the target.

Decoder also allows us to create hashsums of data, as well as providing a Smart Decode feature, which attempts to decode provided data recursively until it is back to being plaintext (like the "Magic" function of Cyberchef).

This interface lays out a multitude of options:
1. A box serves as the workspace for entering or pasting data that requires encoding or decoding. Consistent with other modules of Burp Suite, data can be moved to this area from different parts of the framework via the Send to Decoder option upon right-clicking.
2. At the top of the list on the right, there's an option to treat the input as either text or hexadecimal byte values.
3. As we move down the list, dropdown menus are present to encode, decode, or hash the input.
4. The Smart Decode feature, located at the end, attempts to auto-decode the input.

Upon entering data into the input field, the interface replicates itself to present the output of our operation. We can then choose to apply further transformations using the same options.

## Decoder: Encoding/Decoding

The manual encoding and decoding options:
* **Plain**: This refers to the raw text before any transformations are applied.
* **URL**: URL encoding is utilized to ensure the safe transfer of data in the URL of a web request. It involves substituting characters for their ASCII character code in hexadecimal format, preceded by a percentage symbol (%). This method is vital for any type of web application testing.
* **HTML**: HTML Entities encoding replaces special characters with an ampersand `&`, followed by either a hexadecimal number or a reference to the character being escaped, and ending with a semicolon `;`. This method ensures the safe rendering of special characters in HTML and helps prevent attacks such as XSS.
* **Base64**: a commonly used encoding method, converts any data into an ASCII-compatible format.
* **ASCII Hex**: This option transitions data between ASCII and hexadecimal representations.
* **Hex**, **Octal**, and **Binary**: These encoding methods apply solely to numeric inputs, converting between decimal, hexadecimal, octal (base eight), and binary representations.
* **Gzip**: Gzip compresses data, reducing file and page sizes before browser transmission. Faster load times are highly desirable for developers looking to enhance their SEO score and avoid user inconvenience. Decoder facilitates the manual encoding and decoding of gzip data, although it often isn't valid ASCII/Unicode.

These methods can be stacked. In combination, these methods grant us substantial control over the data we are encoding or decoding.

### Hex Format

While inputting data in ASCII format is beneficial, there are times when byte-by-byte input editing is necessary. This is where "Hex View" proves useful, selectable above the decoding options.

This feature enables us to view and alter our data in hexadecimal byte format, a vital tool when working with binary files or other non-ASCII data.

### Smart Decode

This feature tries to auto-decode encoded text. While not perfect, this feature can be a quick solution for decoding unknown data chunks.

## Decoder: Hashing

In addition to its Encoding/Decoding functionality, Decoder also offers the ability to generate hashsums for our data.

### Theory

Hashing is a one-way process that transforms data into a unique signature. For a function to qualify as a hashing algorithm, the output it generates must be irreversible.

A proficient hashing algorithm ensures that every data input will generate a completely unique hash. Therefore, hashes are commonly used to verify the integrity of files and documents, as even a tiny alteration to the file significantly changes the hashsum.

Moreover, hashes are used to securely store passwords since the one-way hashing process makes the passwords relatively secure, even if the database is compromised.

When a user creates a password, the application hashes and stores it. During login, the application hashes the submitted password and compares it against the stored hash. If they match, the password is correct. Using this method, an application never needs to store the original (plaintext) password.

### Hashing in Decoder

Decoder allows us to create hashsums for data directly within Burp Suite. It operates similarly to the encoding/decoding options earlier. Specifically, we click on the Hash dropdown menu and select an algorithm from the list.

A hashing algorithm's output does not yield pure ASCII/Unicode text. Hence, it's customary to convert the algorithm's output into a hexadecimal string.

## Comparer: Overview

Comparer, as the name implies, lets us compare two pieces of data, either by ASCII words or by bytes.

The interface can be divided into three main sections:
1. On the left, we see the items to be compared. When we load data into Comparer, it appears as rows in these tables. We select two datasets to compare.
2. On the upper right, we have options for pasting data from the clipboard (Paste), loading data from a file (Load), removing the current row (Remove), and clearing all datasets (Clear).
3. Lastly, on the lower right, we can choose to compare our datasets by either words or bytes. It doesn't matter which of these buttons we select initially because this can be changed later. These are the buttons we click when we're ready to compare the selected data.

Just like most Burp Suite modules, we can also load data into Comparer from other modules by right-clicking and choosing **Send to Comparer**.

Once we've added at least 2 datasets to compare and press on either Words or Bytes, a pop-up window shows us the comparison.

This window also has three distinct sections:
1. The compared data occupies most of the window. It can be viewed in either text or hex format. The initial format depends on whether we chose to compare by words or bytes in the previous window, but this can be overridden by using the buttons above the comparison boxes.
2. The comparison key is at the bottom left, showing which colors represent modified, deleted, and added data between the two datasets.
3. The Sync views checkbox is at the bottom right of the window. When selected, it ensures that both sets of data will sync formats. In other words, if we change one of them into Hex view, the other will adjust to match.

## Sequencer: Overview

Sequencer allows us to evaluate the entropy, or randomness, of "tokens". Tokens are strings used to identify something and should ideally be generated in a cryptographically secure manner.

These tokens could be session cookies or Cross-Site Request Forgery (CSRF) tokens used to protect form submissions. If these tokens aren't generated securely, then, in theory, we could predict upcoming token values. The implications could be substantial, for instance, if the token in question is used for password resets.

We have two main ways to perform token analysis with Sequencer:
* **Live Capture**: This is the more common method and is the default sub-tab for Sequencer. Live capture lets us pass a request that will generate a token to Sequencer for analysis. For instance, we might want to pass a POST request to a login endpoint to Sequencer, knowing that the server will respond with a cookie. With the request passed in, we can instruct Sequencer to start a live capture. It will then automatically make the same request thousands of times, storing the generated token samples for analysis. After collecting enough samples, we stop the Sequencer and allow it to analyze the captured tokens.
* **Manual Load**: This allows us to load a list of pre-generated token samples directly into Sequencer for analysis. Using Manual Load means we don't need to make thousands of requests to our target, which can be noisy and resource-intensive. However, it does require that we have a large list of pre-generated tokens.

## Sequencer: Analysis

The generated entropy analysis report is split into four primary sections. The first of these is the **Summary** of the results. The summary gives us the following:
* **Overall result**: This gives a broad assessment of the security of the token generation mechanism.
* **Effective entropy**: This measures the randomness of the tokens. The effective entropy of 117 bits is relatively high, indicating that the tokens are sufficiently random and, therefore, secure against prediction or brute force attacks.
* **Reliability**: The significance level of 1% implies that there is 99% confidence in the accuracy of the results. This level of confidence is quite high, providing assurance in the accuracy of the effective entropy estimation.
* **Sample**: This provides details about the token samples analyzed during the entropy testing process, including the number of tokens and their characteristics.

While the summary report often provides enough information to assess the security of the token generation process, it's important to remember that further investigation may be necessary in some cases. The character-level and bit-level analysis can provide more detailed insights into the randomness of the tokens, especially when the summary results raise potential concerns.

While the entropy report can provide a strong indicator of the security of the token generation mechanism, there needs to be more definitive proof. Other factors could also impact the security of the tokens, and the nature of probability and statistics means there's always a degree of uncertainty. That said, an effective entropy of 117 bits with a significance level of 1% suggests a robustly secure token generation process.

## Organizer: Overview

The Organizer module of Burp Suite is designed to help us store and annotate copies of HTTP requests that we may want to revisit later. This tool can be particularly useful for organizing our penetration testing workflow. Here are some of its key features:
* We can store requests that we want to investigate later, save requests that we've already identified as interesting, or save requests that we want to add to a report later.
* We can send HTTP requests to **Burp Organizer** from other Burp Modules such as **Proxy** or **Repeater**. We can do this by right-clicking the request and selecting **Send to Organizer** or using the default hotkey `Ctrl+O`. Each HTTP request that we send to Organizer is a read-only copy of the original request saved at the point we sent it to Organizer.
* Requests are stored in a table, which contains columns such as the request index number, the time the request was made, workflow status, Burp tool that the request was sent from, HTTP method, server hostname, URL file path, URL query string, number of parameters in the request, HTTP status code of the response, length of the response in bytes, and any notes that we have made.

To view the request and response:
1. Click on any Organizer item.
2. The request and response are both read-only. We can search within the request or response, select the request, and then use the search bar below the request.