---
title: Nmap Commands
excerpt: This post covers basic Nmap commands for Intelligence Gathering using active and passive techniques.
categories:
  - Intelligence Gathering
tags:
  - Nmap
  - Scanning
  - Metasploit
---

This post covers basic Nmap commands for Intelligence Gathering using active
techniques and passive techniques in conjunction with Metasploit.

## Network Discovery

### Simple List
```
nmap -sL 192.168.56.0/24
```

### Ping Scan
```
nmap -sn 192.168.56.0/24
```

## Port Scan

### Basic Port Scan
```
nmap 192.168.56.101
```

### Banner Grabbing Version Scan
```
nmap -sV 192.168.56.101
```

### Aggressive (runs default scripts too)
*will set off IDS/IPS*
```
nmap -A 192.168.56.101
```

### Dont ping to determine if alive
```
nmap -sP 192.168.56.101
```

### Syn Scan
```
nmap -sS 192.168.56.101
```

### Idle Scanning
If we can predict the IP ID of an idle host, we can use it as a zombie.
Idle Incremental IP ID Discovery:

```
msfconsole> use auxiliary/scanner/ip/ipidseq
msfconsole> show options
```

Set RHOSTS and THREADS
When you found an Incremental host, use it with nmap:

```
nmap -PN -sI <ip of found host> 190.168.56.101
```

## Scripts

### Locate scripts

```
ls /usr/share/nmap/scripts/
```

### Run Default Scripts

```
nmap -sC 192.168.56.101 -p <port>
```

### Script Information
```
nmap --script-help=<script name>
```

### Specific script
```
nmap --script=<script name> -p <port>
```
