---
title: Arch Basic Install
excerpt: This post covers the basics of installing Arch Linux in a UEFI/GPT System.
categories:
  - UEFI
  - Linux
tags:
  - UEFI
  - GPT
  - Administration
  - Linux
  - Arch
---

## System Installation

### Load Locals

```
loadkeys fr
timedatectl set-ntp true
```

### Partitioning

**Note: If dual-booting with a Windows, the EFI partition will already exist, and will be used later.**

```
cfdisk /dev/sda
```

Label: GPT

| Device | Size | Type |
|-------:|-----:|-----:|
| /dev/sda1 | 512M | EFI System |
| /dev/sda2 | 2G | Linux Swap |
| /dev/sda3 | 17.5G | Linux Filesystem |

```
mkfs.fat -F32 /dev/sda1
mkfs.ext4 /dev/sda3
mkswap /dev/sda2
swapon /dev/sda2
```

### Mounting the new drives

```
mount /dev/sda3 /mnt
mkdir /mnt/boot
mount /dev/sda1 /mnt/boot
```

### Installing the system

```
cp /etc/pacman.d/mirrorlist /etc/pacman.d/mirrorlist.bak
rankmirrors -n 6 /etc/pacman.d/mirrorlist.bak > /etc/pacman.d/mirrorlist
pacstrap -i /mnt base base-devel
genfstab -U /mnt > /mnt/etc/fstab
```

### Configuring the system

```
arch-chroot /mnt
ln -s /usr/share/zoneinfo/Europe/London /etc/localtime
hwclock --systohc # assumes UTC
nano /etc/locale.gen # uncomment en_GB.UTF-8 UTF-8
locale-gen
nano /etc/locale.conf
```

/etc/locale.conf:

> LANG=en_GB.UTF-8


```
nano /etc/vconsole.conf
```

/etc/vconsole.conf:

> KEYMAP=fr


```
nano /etc/hostname
```

/etc/hostname:

> coffeemachine


```
nano /etc/hosts
```

/etc/hosts:

> 127.0.0.1   localhost.localdomain   localhost

> ::1         localhost.localdomain   localhost

> 127.0.1.1	  coffeemachine.localdomain	  coffeemachine

```
passwd
#sudo pacman -S intel-ucode # if you're running intel
```

### Bootloader

**Note: Windows will be auto-detected. Linux needs a manual entry for each Linux.**

```
bootctl --path=/boot install
```

/boot/loader/loader.conf:

```
default  arch
timeout  4
```

the command ```lsblk``` can be used to get PARTUUID value. It's the / partition, not EFI partition

/boot/loader/entries/arch.conf

```
title   Arch Linux
linux   /vmlinuz-linux
# initrd  /intel-ucode.img # uncomment if on Intel system
initrd  /initramfs-linux.img
options root=PARTUUID=91f578a1-e7d9-4af5-ac83-8c6393154443 rw
```
