# Raspbian Secure Server Config Tutorial (R.S.S.C.T)

# Description

Let's build a server at home with a RaspberryPI, a minimal optimized [Raspbian](https://www.raspbian.org/) OS, configure it, secure it, hide it, test it and of course, enjoy it!

This tutorial is for Raspberry Pi Model 1B, 1B+ and 2B, a minimal microSD card of 8GB (i'm using a 95mb/s 64GB) and the standard RPi 1GB of RAM memory

Here follow the detailed process of building the server, let's make coffee and get to it!


# Install

First of all, we want to start with a minimal version of Raspbian, something similar to the [netinst version of Debian](https://www.debian.org/CD/netinst/), so i searched the web (not googleed, i prefer to use [DuckDuckGo](https://duckduckgo.com/) because they do not track you, or at least it seems so) and i find a great contribution from [debian-pi](https://github.com/debian-pi) github user, the [raspbian-ua-netinst](https://github.com/debian-pi/raspbian-ua-netinst) repo, a Raspbian (minimal) unattended netinstaller!

Amazing!

So, follow the repo instructions, download the last release installer and flash the SD card. Easy.
The second step is to put the flashed SD card in your RPi, power on and wait, the installer will boot your RPi, connect to the internet (you need to connect the RPi with an ethernet cable), downloading the latest version of Raspbian, and installing it. Depending on your internet connection speed you will have to go for another coffee, or not.

When this step is finished you will have a minimal Raspbian system with ssh enabled by default, the root account with password: raspbian, and all the necessary basic command line tools. (you can check the details in the [raspbian-ua-netinst](https://github.com/debian-pi/raspbian-ua-netinst) repo)

If everything went ok, now you can ssh into your RPi with {user : root, password: raspbian}:

```bash
ssh root@RPI_ip_number
```

Let's print some system info, first the running kernel version:

```bash
cat /proc/version
```
my output:

```bash
Linux version 4.4.0-1-rpi2 (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Raspbian 4.9.2-10) ) #1 SMP Debian 4.4.6-1+rpi14 (2016-05-05)
```
The Linux distribution and version:

```bash
cat /etc/*release*
```

my output:

```bash
PRETTY_NAME="Raspbian GNU/Linux 8 (jessie)"
NAME="Raspbian GNU/Linux"
VERSION_ID="8"
VERSION="8 (jessie)"
ID=raspbian
ID_LIKE=debian
HOME_URL="http://www.raspbian.org/"
SUPPORT_URL="http://www.raspbian.org/RaspbianForums"
BUG_REPORT_URL="http://www.raspbian.org/RaspbianBugs"
```

The block devices:

```bash
lsblk
```
my output (with 64GB SD card):

```bash
NAME        MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
mmcblk0     179:0    0  59.5G  0 disk
├─mmcblk0p1 179:1    0 122.1M  0 part /boot
└─mmcblk0p2 179:2    0  59.4G  0 part /
```

This is just the beginning! In the next session we'll make a little post-install configuration, just the suggestions from [raspbian-ua-netinst](https://github.com/debian-pi/raspbian-ua-netinst) repo, next story, "Post-Install Config".

# Post-Install Config

1 - Set new root password:

```bash
passwd
```

2 - Configure your default locale

```bash
dpkg-reconfigure locales
```

3 - Configure your timezone

```bash
dpkg-reconfigure tzdata
```

4 - Improve memory management performance

```bash
apt-get install raspi-copies-and-fills
```

5 - Install and auto-load and use the kernel module for the hardware random number generator. This improves the performance of various server applications needing random numbers significantly.

```bash
apt-get install rng-tools && echo "bcm2708-rng" | tee -a /etc/modules
```

6 - Create a 1GB SWAP file, and enable it on boot modifing fstab file:

```bash
dd if=/dev/zero of=/swap bs=1M count=1024 && mkswap /swap && chmod 600 /swap
echo "/swap none swap sw 0 0" | tee -a /etc/fstab
```

Ok, we have our basic Raspbian server post installation!

I'm curious at this moment about things like [Attack Surface](https://en.wikipedia.org/wiki/Attack_surface), let's print some information:

```bash
find / -perm -4000 -print
```

This command will list potential 'vulnerable' system points, listing all executable files with [SUID](https://en.wikipedia.org/wiki/Setuid) . My output:

```bash
/bin/mount
/bin/umount
/bin/su
```

basically SUID flag allow a user to run an executable with the permissions of the executable owner, so if someone finds a vulnerability in one of this programs and exploits it, GAME OVER, he/she will have root permissions on the system, goodbye Raspbian Secure Server!!!

But don't worry, we are just getting started, a long journey awaits us, with so much to learn.

Let's install and configure all the essentials for our Raspbian Secure Server, next story, "Configuration".

# Configuration

We will need to get confortable with edit a lot of text files, maybe some programming too :P, so we begin installing our favorite console text editor, i'm going to use "nano", but there are better options like "vim", choose here whatever suits you:

```bash
apt-get install nano
```

And customize it by adding line numbering:

```bash
nano /etc/nanorc
```

Uncomment # set const to add line numbering:

```bash
# set const
set const
```

## Users

Create a new user with regular account privileges (change "user" with your username of choice):

```bash
adduser user
```

Follow instructions, fill all the fields you want, and most important, enter a strong password.

Create a new SSH Key Pair for securing the server with a public key authentication for the new user:

1 - **On your local machine**, generate a key pair:

```bash
ssh-keygen -t rsa -b 4096 -C "raspbian_rsa"
```

Choose the name of the key (Ex. myKey) files and set a password
This generates a private key "myKey" and a public key "myKey.pub", in the .ssh directory of the localuser's home directory. Remember that the private key should not be shared with anyone who should not have access to your servers!

2 - **On your local machine**, copy the public key to our server:

```bash
ssh-copy-id -i myKey.pub user@RPI_ip_number
```

That's it, now we may SSH login to our server using the private key as authentication, so the time has come for configuring our SSH daemon for better security

Let's open the SSH configuration file:

```bash
nano /etc/ssh/sshd_config
```

And change:

1 - Disallow SSH access to root account

```bash
PermitRootLogin no
```

2 - Disable X11Forwarding:

```bash
X11Forwarding no
```

3 - Add AllowUsers user, in order to enable access for your new user ONLY:

```bash
AllowUsers user
```

4 - Disable tunneled cleartext password authentication and enable SSH public key only access

```bash
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile      %h/.ssh/authorized_keys
```

5 - Save the file (ctrl o), close it (ctrl x) and restart the ssh service:

```bash
/etc/init.d ssh restart
```

6 - **On your local machine**, Log out and ssh login to check, now with your generated ssh key, normal cleartext password is now disabled.

```bash
ssh -i ~/.ssh/your_rsa_key_name -p 22 username@RPi_ip_number
```

For the most curious, -i specify the identity_file (your private key from the key pair), and -p specify the port where to connect (22 is the standard ssh port).

7 - For more info about securing services, take a look at the [debian manual](https://www.debian.org/doc/manuals/securing-debian-howto/ch-sec-services.en.html)

Ok, user configuration and SSH login secured and tested, if everything is working correctly, next story, "Net".

## Net

So, basically, at this stage we want to connect our Raspbian Server at our local network via ethernet cable and ssh into it to continue installing and configuring stuff, and probably we are not going to do that always at the same place, sometimes we will working on that from home, and maybe sometimes we are going to work from a friend house, or a co-working somewhere, or whatever.
The point is, we don't want to check every time the IP number of our RPi, we don't want to have DHCP (default) assign a new IP every time we connect our RPi to a new router, so we disable DHCP and assign a static IP. That means, our Raspbian Server, locally, will always have the IP we choose. This is really trivial, so let's do it.

1 - Open the file /etc/network/interfaces

```bash
nano /etc/network/interfaces
```

2 - You'll see a line like this:

```bash
iface eth0 inet dhcp
```

This is the default configuration for eth0, the RPi standard ethernet device, with DHCP enabled. [DHCP](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol) is a protocol commonly used by the vast majority of routers to dinamically assign a free IP to the connected device. It's really the easy choice, but we don't want that here (not because of the "easy" part), we just want our RPi to have alwais the same IP number (static).

3 - So we comment the default DHCP config line and we add a static IP:

```bash
#iface eth0 inet dhcp
iface eth0 inet static
  address your.static.ip.number Ex. 192.168.1.59
  netmask 255.255.255.0
```

The address and netmask goes accordingly with your router configuration, but the above example is really common

4 - Save the file and close it

We have it! Try rebooting your RPi and check for the eth0 assigned IP:

```bash
ifconfig eth0 | grep inet
```

If everything is correct, your output will show the IP and netmask you configured in the /etc/network/interfaces file

Ok, so pack your RPi with an ethernet cable, and stuff it in your bag, now we will be able to work at our server at any place with a router; we connect the RPi, start it up, and from another computer connected to the same router we ssh to our server, great!

Let's take a look now at a really useful tool for when we are working with network stuff, [netstat](https://www.lifewire.com/netstat-linux-command-4095695)

```bash
netstat -apt
```

This will output all(listening and established) active tcp connections, my output:

```bash
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 RPi.static.ip:22        *:*                     LISTEN      294/sshd        
tcp        0      0 RPi.static.ip:22        client.ip.number:22     ESTABLISHED 388/sshd: username
```

Everything seems ok, we have our SSH daemon listening and our active ssh connection established.

We will use this tool a lot, so check it out and get comfortable with it ;

continue...

## Services

## Security

## Hardening

## Hide

## Attack (Testing)

## Your 50€ dedicated server (50DS)
