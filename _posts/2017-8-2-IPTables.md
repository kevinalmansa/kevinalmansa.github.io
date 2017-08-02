---
title: IPTables
excerpt: This post is created to both introduce and serve as a reference to the Linux firewall IPTables.
categories:
  - Network Security
tags:
  - firewall
---

In this post we'll explore a bit the basics of the Linux Firewall, IPTables. I'm
going to try and structure this post so that is can serve as an introduction to
IPTables, but also as a reference to quickly look up forgotten commands.

This post will begin by introducing IPTables, detailing the concepts behind it
and how it works. We'll then move towards configuring it with the command line
interface.


## What is IPTables

As described in the IPTables manual, "iptables and ip6tables are used to set up,
maintain, and inspect the tables  of IPv4 and IPv6 packet filter rules in the
Linux kernel.". In other words, its a command line utility that allows a system
administrator to interact with the kernel's built-in firewall (the Netfilter
Project).

IPTables with the Netfilter Project filters traffic from the network layer up to
the application layer in the OSI Model. This is important to note because
protocols such as ARP which reside in the Data-Link layer will not be filtered.
That being said, IPTables CAN filter on Data-Link MAC address, but only if the
kernel is compiled accordingly (default since Linux kernel 2.6).

### Tables

IPTables get's it's name from it's design. It uses five tables which construct
it's functionality:

  1. `filter` the default table. This holds all actions typical of a firewall.
  2. `nat` Network Address Translation (port forwarding).
  3. `mangle` used for packet alterations.
  4. `raw` used for configuring packets so that they are exempt from connection
  tracking.
  5. `security` used for *Mandatory Access Control* networking rules (ex.
    SELinux).

The most commonly used tables are **filter** and **nat**.

### Chains

Tables themselves consist of *Chains*; lists of rules followed in order. Each
table has a default set of chains, with the chains for `filter` and `nat` being:

| Table          | Chains                          |
| :------------- | :-------------------------------|
| filter         | INPUT, OUTPUT, FORWARD          |
| nat            | PREROUTING, POSTROUTING, OUTPUT |

For the others, please consult the manual.

An overview of the packet flow through these two tables and their respective
chains can be seen with the image bellow.

![iptables flow](/assets/images/iptables/iptables.jpg)
*Figure 1. from Linux Firewalls (Michael Rash, 2007)*

User-defined chains may also be created to group a common set of rules.

By default, the chains do not contain any rules, but they *do* have a default
policy which applies at the end of a chain ONLY. **User defined chains can not**
**have a default policy**. The default policy can be either `ACCEPT` or `DROP`
depending on whether you want a *black-list* or *white-list* approach to
filtering.

### Rules

Finally, we have rules. Rules filter the packets by specifying one or multiple
*matches* and one *target* (the action to take when a packet matches all
conditions).

#### Matches

A *match* is simply a set of conditions that must be met by a packet for it to
be processed with an action taken. Examples in general firewalls are
source/destination IPs, ports, interfaces, etc. IPTables is no different.

Common matches in IPTables include:

| Match               | Description     |
| :-------------------| :---------------|
| --source (-s)       | Matches on a source IP or network      |
| --destination (-d)  | Matches on a destination IP or network |
| --protocol (-p)     | Protocol to match. ex. all, tcp, udp, icmp... |
| --in-interface (-i) | Input interface (ex: eth0)              |
| --out-interface (-o)| Output interface                        |
| --dport             | Destination port                        |
| --sport             | Source port                             |
| --state             | Extension. Match on a set of connection states: INVALID, ESTABLISHED, NEW, RELATED, UNTRACKED. |
| --string            | Extension. Match on a sequence of application layer data bytes  |
| --comment           | Extension. Allows you to add comments to rules |

#### Targets

Targets, the action taken when a packet matches all conditions, are either
built-in, or provided via a *target extension*.

Although a target is typically an action, it can also be a *user-defined*
*chain*, which would then be used to continue processing.

The most common targets are:


| Target              | Description     |
| :-------------------| :---------------|
| ACCEPT              | Allows the packet to continue through other tables.|
| DROP                | Drops the packet. No further processing applied.   |
| QUEUE               |                                                    |
| RETURN              | Stop traversing this chain and resume at the next rule calling chain. |
| LOG                 | Extension. Logs the packet to syslog.              |
| REJECT              | Extension. Drops the packet and sends an appropriate response.|

Targets are specified using the `-j` or `--jump` option.

### Summery

IPTables is the standard Linux Firewall that operates from the Network Layer to
the Application Layer in the OSI Model. As seen throughout this section, rules
are made up of conditions, referred to as *matches*, and an action, referred to
as a *target*. Rules themselves are stored in lists, referred to as *chains*,
which are stored in one of the five *tables*. Default chains are invoked at
different aspects of the packet flow through the filtering system allowing for a
fine-grained control.

In the next section, we'll look at interacting with IPTables through the command
line interface. We'll demonstrate how to backup a configuration, administrate
rules and chains, as well as cover some of the more commonly used rules.

## IPTables Command Line

This section will demonstrate essential and commonly used IPTables commands. It
is formatted in such a way that I hope it may be used as a reference as well.
Please note as well, the `iptables` command require root privileges.

An important note to keep in mind throughout this section: all `iptables`
commands default to the `filter` table. To specify another table, use the
`-t` option; `iptables -t nat`.

Also, before trying any of these commands, please bare in mind if you are not
locally on the machine and you DROP or REJECT network connections, you will be
kicked out of your session by the firewall.

Please do not forget to backup your configuration before modifying IPTables.

### IPTables Configuration

```sh
$ iptables-save > /etc/iptables/iptables.rules      # Save current configuration
$ iptables-restore < /etc/iptables/iptables.rules   # Restore configuration
```

### List current rules

```sh
$ iptables --list-rules
$ iptables -S             # same command as above
```

or for more information:

```sh
$ iptables -nvL
```

### Show Line Numbers

Useful when editing rules.

```sh
--line-numbers
```

### Set default policy

```sh
$ iptables -P FORWARD DROP
```

Only use the above if you do not route packets.

### Create user defined chain

```sh
$ iptables -N MY_NEW_CHAIN
```

### Using user defined chain

```sh
$ iptables -A INPUT -p tcp --dport 80 -j MY_NEW_CHAIN -m comment --comment "Use new chain to process http"
```

also useful, retrieved via the Arch Wiki
[Simple stateful firewall](https://wiki.archlinux.org/index.php/simple_stateful_firewall):

```sh
$ iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$ iptables -A INPUT -p udp -m conntrack --ctstate NEW -j UDP
$ iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j TCP
$ iptables -A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable
$ iptables -A INPUT -p tcp -j REJECT --reject-with tcp-reset
```

The first rule allows all previously established or active connections. The next
two rules set the *target* to the user defined chain *UDP* and *TCP* upon a new
*UDP* or *TCP* packet. The last two then reject all other UDP and TCP
attempts to unopened ports.

This allows for TCP rules (such as opening ports, logging, etc) to be handled in
the user defined chain *TCP*, and UDP rules to be handled in the *UDP* chain.

### Editing Rules
Rules can be appended (```-A```), inserted (```-I```) to a specific position,
replaced (```-R```) or deleted (```-D```).

```sh
$ iptables -A INPUT -p tcp --dport 22 -j REJECT --reject-with icmp-port-unreachable
```

```sh
$ iptables -R INPUT 1 -p tcp --dport 22 ! -s 10.0.0.85 -j REJECT --reject-with icmp-port-unreachable
## Replaces the first rule in INPUT. ! -s 10.0.0.85 means to allow 10.0.0.85
## This rule does not scale well...thus let's add the rule bellow first!
```

```sh
$ iptables -I INPUT -p tcp --dport 22 -s 10.0.0.85 -j ACCEPT -m comment --comment "Friendly SSH connection"
## Now let's replace the rule shown before!
```

```sh
$ iptables -R INPUT 2 -p tcp --dport 22 -j REJECT --reject-with icmp-port-unreachable
```

### Allow local data

```sh
$ iptables -A INPUT -i lo -p all -j ACCEPT -m comment --comment "Allow All Local Traffic"
```

### Allow existing connections

```sh
$ iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

or

```sh
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

### Allow ping

```sh
$ iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
```

or

```sh
$ iptables -A INPUT -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT
```

### Safe Defaults

```sh
$ iptables -P INPUT DROP
$ iptables -P FORWARD DROP
$ iptables -P OUTPUT ACCEPT
```

**NOTE:** As previously mentioned, if you are not locally in front of the
machine, the above CAN disconnect your remote session and WILL require you to
locally modify it, or reboot the machine. **TREAD CAREFULLY**.

### Drop Invalid Packets

This drops packets with invalid checksums, invalid headers, invalid ICMP, and
out of sequence packets.

```sh
$ iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
```

### More Examples

More examples can be found bellow:

https://linuxconfig.org/collection-of-basic-linux-firewall-iptables-rules
https://wiki.archlinux.org/index.php/simple_stateful_firewall
