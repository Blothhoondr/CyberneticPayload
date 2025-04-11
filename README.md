# Common Commands I Use Frequently

## Enumeration
### Port Scanning
- `IP=x.x.x.x`
- `sudo masscan -p1-65535 $IP --rate=1000 -e tun0 > ports`
- `ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')`
- `nmap -Pn -sVC -vv -p$ports $IP`
### Web Directory Fuzzing
- `ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://xxxxxx.xxx/FUZZ -fc 404,400`

## Encryption/Decryption
