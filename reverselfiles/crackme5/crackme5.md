# Reversing ELF

## Task 5 - Crackme5

* Category: Reverse Engineering
* Difficulty: **Easy**

### Challenge

We received a binary file named `crackme5`. Let's try to run the binary.

![](test-run.png)

That didn't go well. We need to input something for it to say `Good game`. Let's try using `strings` to see if we can find any hints.

![](strings-binary.png)

Tough luck. The password is hidden. Let's try using `radare2` to analyze the binary.

![](main-function.png)

We found some kind of suspicious array of characters. It is passed into a `strcmp_` function with our input. Let's check it out.

![](strcmp_-function.png)

The function uses `strncmp` to compare our input with the array of characters. The number of characters to compare is 28. Let's try the string made up of 28 first characters of the array that we found.

![](success.png)

And GG! We move on to the next one.