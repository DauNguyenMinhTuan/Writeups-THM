# Daily Bugle

## Description

Compromise a Joomla CMS account via SQLi, practise cracking hashes and escalate our privileges by taking advantage of yum.
* **Difficulty:** **Hard**
* **Categories:** SQLi, Reverse Shell, Password Cracking, Privilege Escalation

## Write-up

As always, we received an IP address. We start by enumerating it with nmap.

![](nmap.png)

We can see there is a web server running on port 80. There seems to be a Joomla CMS running on the same server. Apart from that, there is an SSH server running on port 22 and a MySQL server running on port 3306. It's a good idea to start by checking out the web server.

![](daily_bugle-front-page.png)

This is a front page of Daily Bugle. We can see that there is a login page of what we assumed to be a Joomla CMS. Let's run gobuster to find any hidden directories.

![](gobuster.png)

We can see a lot of directories here, many of which are Joomla related. There are `.txt` files as well. Let's check them out before we move on to the `administrator` directory.

![](README-txt.png)

The `README.txt` shows us that the Joomla version is `3.7`. Let's check out the `LICENSE.txt` file.

![](LICENSE-txt.png)

Nothing much here. Let's move on to the `htaccess.txt` file.

![](htaccess-txt.png)

It seems like the `htaccess.txt` file is trying to block us from seeing the directory listing. Let's move on to the `robots.txt` file.

![](robots-txt.png)

Nothing much that we haven't known already. Let's move on to the `administrator` directory.

![](administrator-login.png)

The `/administrator` directory is the login page for the Joomla CMS. We don't have any credentials to login. Since we know the Joomla version, let's try to find if there are any vulnerabilities for this version.

![](joomla-vuln-search.png)

As we look up for the Joomla version on Exploit-DB, we find several SQL injection vulnerabilities related to Joomla 3.7. One of them is `CVE-2017-8917`. Let's try to exploit this vulnerability. We found a Python script that can exploit this vulnerability. Let's run it.

![](joomblah-exploit.png)

The script was able to give us the username and the password hash. Let's crack the hash using `john`.

![](password-cracked.png)

We found the password for the user `jonah`. Let's login to the Joomla CMS using these credentials.

![](joomla-dashboard.png)

After looking around, we found the template manager. Let's try to load a reverse shell using the template manager. First, there are 2 templates available. We need to modify the `index.php` file of the template to check which one is being used.

![](protostar-template-test.png)

Now we go back to the front page of Daily Bugle to check.

![](template-verified.png)

We can confirm that the `protostar` template is being used. Now we add the Monkey reverse shell to the `index.php` file of the `protostar` template.

![](template-reverse-shell-loaded.png)

Now we start a listener on our machine and visit the front page of Daily Bugle.

![](reverse-shell-connected.png)

We have a reverse shell. Let's upgrade it to a TTY shell.

![](stable-reverse-shell.png)

Now time to look around. From the gobuster scan, we knew that there was a `configuration.php` file. Let's check it out.

![](configuration-php.png)

All the database credentials are here. We can of course use these credentials to login to the MySQL server. But let's look around more.

![](user-enum.png)

We found a user `jjameson`. Let's try to login with SSH using this username.

![](ssh-login.png)

We are in. Let's look around.

![](user-flag.png)

We found the user flag. Now let's escalate our privileges. Let's start by running `sudo -l`.

![](sudo_l.png)

We can see that we can run `sudo yum` without a password. Let's try to exploit this.

![](GTFO-yum.png)

With the help of GTFOBins, we were able to escalate our privileges. Let's read the root flag.

![](root-flag.png)

And that's it. We have finished the Daily Bugle room.