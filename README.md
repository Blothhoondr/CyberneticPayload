# Common Commands I use

## Enumeration
- IP=x.x.x.x
- sudo masscan -p1-65535 $IP --rate=1000 -e tun0 > ports
- ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
- nmap -Pn -sVC -vv -p$ports $IP
