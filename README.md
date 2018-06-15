# Deception-AutoConfig
Large scale, automatic configuration of honeyports and other common deception techniques on Windows hosts

This project aims to automate deception techniques at a large scale.  The techniques themselves are drawn from well-known projects, but this project addresses a common component that is missing - deployment at scale. Simply run this script on all Windows hosts, and it will implement each technique.  

Fully implemented, you will have: 
 - A sea of honeypots, with all systems listening on exactly the same ports and only a few of which are hosting real services
 - Hidden directories on each system with auditing enabled to alert you on access attempts
 - Honey Credentials in Scheduled Tasks for tools like Mimikatz to dump and trigger alerts
 
## Sea of Honeypots

Imagine you're scanning a network with nmap, but every single server looks exactly the same. It looks something like this:

```
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-15 10:17 Eastern Daylight Time
Nmap scan report for host1.jj.local (10.19.5.68)
Host is up (0.013s latency).
Not shown: 982 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
23/tcp    open  telnet
25/tcp    open  smtp
53/tcp    open  domain
80/tcp    open  http
110/tcp   open  pop3
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
1521/tcp  open  oracle
1723/tcp  open  pptp
2701/tcp  open  sms-rcinfo
5800/tcp  open  vnc-http
8080/tcp  open  http-proxy
10000/tcp open  snet-sensor-mgmt
16993/tcp open  amt-soap-https
44443/tcp open  coldfusion-auth
```

Cool honeyports... That's so old school, right? But this is now on EVERYTHING.  An attacker sees this report for every host scanned. We make them work harder to find the database servers (or whatever they're after) from a network access perspective. 

This works by simply port forwarding the honeyports to an actual honeypot system on the backend.  For example, you can spin up Kippo to listen on port 22, SpiderTrap to listen on 80, Artillery to listen on everything else.  That way, a connection to any host on a honeyport will end up at an actual, listening service to further entrap the attacker.

## Honey Directories

Users click lots of links, send their passwords to those who ask nicely, etc.  Honey directories are a proven method for detecting unauthorized access on legitimate systems.  This script creates a hidden directory and sets up the appropriate auditing policy to alert whenever it is accessed.  

## Honey Credentials

The attackers on your internal network are on a credential scavenger hunt.  They're looking to find credentials that allow for horizontal or vertical privilege escalation, and it makes them happy to find creds that look powerful.  This script creates a scheduled task running as a domain user, and expects it to be compromised.  Make sure you run the provided commands to disable logon hours for this user prior to leaving the scheduled tasks available to be 'compromised.'

## DNS Zones

If the autoconfig script finds itself running on a DNS server, it can inject a new zone and enable zone transfers. Then, watch for the event ID on that zone being transferred to find additional network-based reconnaissance occurring on the network.






