# raspbian Secure Server Config Tutorial (R.S.S.C.T)

## Description

Let's build a server at home with a RaspberryPI, a minimal optimized [Raspbian](https://www.raspbian.org/) OS, configure it, secure it, hide it, test it and of course, enjoy it!

This tutorial is for Raspberry Pi Model 1B, 1B+ and 2B, a minimal microSD card of 8GB (i'm using a 95mb/s 64GB) and the standard RPi 1GB of RAM memory

Here follow the detailed process of building the server, let's make coffee and get to it!


## Install

First of all i wanted to start with a minimal version of Raspbian, something similar to the [netinst version of Debian](https://www.debian.org/CD/netinst/), so i searched the web (not googleed, i prefer to use [DuckDuckGo](https://duckduckgo.com/) because they do not track you, or at least it seem so) and i find a great contribution from [debian-pi](https://github.com/debian-pi) github user, the [raspbian-ua-netinst](https://github.com/debian-pi/raspbian-ua-netinst) repo, a Raspbian (minimal) unattended netinstaller!

Amazing!

So, followed the repo instructions, downloaded the last release installer and flashed the SD card. Easy.
The second step is put the flashed SD card in your RPi, power on and wait, the installer will boot your RPi, connect to the internet (you need to connect the RPi with an ethernet cable), downloading the latest version of Raspbian, and installing it. Depending on your internet connection speed you will have to go for another coffee, or not.

When this step is finished you will have a minimal Raspbian system with ssh enabled by default, the root account with password: raspbian, and all the necessary basic command line tools. (you can check the details in the [raspbian-ua-netinst](https://github.com/debian-pi/raspbian-ua-netinst) repo)

If everything went ok, now you can ssh into your RPi with:

```bash
ssh root@RPI_ip_number
```

## Post-Install Config

```bash
dpkg-reconfigure locales
dpkg-reconfigure tzdata
apt-get install raspi-copies-and-fills
apt-get install rng-tools
apt-get install bash-completion
```

Create SWAP file:

```bash
dd if=/dev/zero of=/swap bs=1M count=1024 && mkswap /swap && chmod 600 /swap
```

Append /swap none swap sw 0 0 to /etc/fstab:

```bash
echo "/swap none swap sw 0 0" | tee -a /etc/fstab
```

Add bcm2708-rng to /etc/modules to auto-load and use the kernel module for the hardware random number generator:

```bash
echo "bcm2708-rng" | tee -a /etc/modules
```

## Configuration

# Users

# Net

# Services

# Security

# Hardening

# Hide

# Attack (Testing)

# Your 50€ personal server

# License
