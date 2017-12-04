# fail2ban-logzio
This Action for fail2ban allow recover information from shodan and send it to logzio elk. 

## Requirements

You must have up-to-date the following packages on your system: 

```bash
pip install --upgrade pip 
pip install --upgrade -r requirements.txt 
```
And *fail2ban >= 0.10*

You must have an account in logzio and shodan in order to retrieve the information

## How to use it
- Copy the file ElkAction.py to your action folder by default on **/etc/fail2ban/actions.d/**

- Modify your jail config (/etc/fail2ban/jail.conf) to add **ElkAction**:
```
[ssh]

enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime = 900
action = ElkAction.py[shodan_token="shodan_token",logzio_token="logzio_token"]
         iptables-allports
findtime = 900
```

Enjoy :D