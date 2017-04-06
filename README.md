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
apt-get install rng-tools
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

First of all, install some package downloader utils:

```bash
apt-get install apt-utils
```

We will need to get comfortable with edit a lot of text files, maybe some programming too :P, so we begin installing our favorite console text editor, i'm going to use "nano", but there are better options like "vim", choose here whatever suits you:

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

First of all, we need to install **sudo**, a program designed normal users to execute some commands as root, and why is that? Because it's safer than always opening root sessions, nobody will need to know the root password, every execution will be logged and so on with a few more security related reasons.

```bash
apt-get install sudo
```

Create a new user with regular account privileges (change "user" with your username of choice):

```bash
adduser user
```

Follow instructions, fill all the fields you want, and most important, enter a strong password.

Now we need to add the new user to the sudo group, in order to grant sudo capabilities:

```bash
adduser user sudo
```

My output:

```bash
Adding user 'user' to group 'sudo'
Adding user user to group sudo
Done.
```

In order to apply the new group assign log out and log in again.

Next story, SSH

### SSH

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

Now let's harden our SSH for protection against [brute force attacks](https://en.wikipedia.org/wiki/Brute-force_attack), installing **fail2ban**

### Fail2ban (Special Section)

fail2ban provides a way to automatically protect virtual servers from malicious behavior. The program works by scanning through log files and reacting to offending actions such as repeated failed login attempts.

```bash
apt-get install fail2ban
```

Now make a local copy of the configuration file:

```bash
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

And go on configuring it (the elegant stuff):

```bash
nano /etc/fail2ban/jail.local
```

We start with the [DEFAULT] section, edit this lines:

```bash
ignoreip = 127.0.0.1/8 192.168.1.0/24
bantime  = 3600
maxretry = 3
```

This will whitelist the local direction (127.0.0.1/8) and the local net (192.168.1.0/24), and ban a malicious ip after 3 wrong login intents, for 1 hour (3600 seconds).

Now to the [JAILS] section, under ssh you'll see:

```bash
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 6
```

This are the specific settings for SSH service, we don't need to change it, but in case you change the standard port for ssh (22) to another, you'll need to set it up:

```bash
port     = 33000 # for example
```

Perfect, we have it, save the file, close it and restart fail2ban:

```bash
/etc/init.d/fail2ban restart
```

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

This is the default configuration for eth0, the RPi standard ethernet device, with DHCP enabled. [DHCP](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol) is a protocol commonly used by the vast majority of routers to dynamically assign a free IP to the connected device. It's really the easy choice, but we don't want that here (not because of the "easy" part), we just want our RPi to have always the same IP number (static).

3 - So we comment the default DHCP config line and we add a static IP:

```bash
#iface eth0 inet dhcp
iface eth0 inet static
  address your.static.ip.number # Ex. 192.168.1.59
  gateway your.router.ip.number # Ex. 192.168.1.1
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

Everything seems ok, we have our SSH daemon listening at port 22 and our active ssh connection established.
Port 22 is the standard port for SSH, and what are the standard port numbers for other services? To answer that, the best thing we can do is to take a look at the list of common standard ports in a server.

Super easy, just take a look at the /etc/services file:

```bash
cat /etc/services
```

So services and ports, and netstat, we will use this tool a lot, so check it out and get comfortable with it ;

Ok, we'll hit pause right here, it's the update/dist-upgrade moment, we'll repeat this step a number of times over the entire server configuration:

```bash
apt-get update && apt-get dist-upgrade
```

To obtain all the updates for our current raspbian system, and:

```bash
apt-get clean
```

To clean disk space removing temporary updates installation files.

In one line:

```bash
apt-get update && apt-get dist-upgrade -y && apt-get clean
```

So far so good, we have now a decent secure access door to our Raspbian server, we can now start installing and configure all our services, more or less depending on what we'll need from our server, but this is the next chapter so, see you in a bit.

## Services

From [wikipedia](https://en.wikipedia.org/wiki/Server_(computing)): "Servers can provide various functionalities, often called 'services',  such as sharing data or resources among multiple clients, or performing computation for a client."

![CERN First WWW Server](https://upload.wikimedia.org/wikipedia/commons/2/2c/First-server-cern-computer-center.jpg)
**The first HTTP web server of the history, year 1990 (from CERN, where they actually invented the web!)**

Why are we building a server? This is what you need to ask yourself just now! Because depending on what the answer will be, the content of this chapter will eventually change a lot, but anyway, we'll tray to stay cool and cover at least all the basic services, and maybe something more, but enough with the chatting, let's get to it.
There is no better or specific order to install services, in general at least, so i will use mine but you feel free to change it, and of course contributions are welcome and really appreciated.

### SFTP

So, we'll start with implementing a SFTP service with a Chroot'ed Isolated File Directory, WHAAAAAAAAT?

Well, yes, it's not double click on the icon :P, but we are trying to be pro here, and the tutorial title say "Secure Server Config..." so, but don't worry, we'll crack it step by step.

**Step 1**, what is SFTP? From [digitalocean](https://www.digitalocean.com/community/tutorials/how-to-use-sftp-to-securely-transfer-files-with-a-remote-server) : "it stands for SSH File Transfer Protocol, or Secure File Transfer Protocol, is a separate protocol packaged with SSH that works in a similar way over a secure connection. The advantage is the ability to leverage a secure connection to transfer files and traverse the filesystem on both the local and remote system."

**Step 2**, what in the hell means chroot'ed? From [wikipedia](https://en.wikipedia.org/wiki/Chroot) : "A chroot on Unix operating systems is an operation that changes the apparent root directory for the current running process and its children. A program that is run in such a modified environment cannot name (and therefore normally cannot access) files outside the designated directory tree. The term "chroot" may refer to the chroot(2) system call or the chroot(8) wrapper program. The modified environment is called a chroot jail."

**Step 3**, in short, let's implement a secure difficult hackable file transfer protocol service for our Rasbian Server, yheaaaaaa! With this service we will be able to safe connect with our server and upload files, including let someone else access to our server to upload/download files, but in a chroot jail environment, like a bubble with no exits, a chroot environment is the only observable universe, so the rest of the system where we don't want anyone peeking or worse (see [Directory traversal attack](https://en.wikipedia.org/wiki/Directory_traversal_attack)), will not exists.

**Step 4**, install OpenSSH server software

```bash
apt-get install openssh-server
```

**Step 5**, create a users group for sftp access and a specific user, this is a good practice for every kind of services, create specific groups for every service in order to limit access, if i will connect via sftp, i will have access to ONLY that.

```bash
groupadd sftpgroup
```

```bash
cat /etc/group
```

Take note here of the id related with the newly created group, in my case is 1001:

```bash
sftpgroup:x:1001:
```

Add now a new user that we will use exclusively for SFTP access (change 1001 with your group id, and choose your user name):

```bash
sudo useradd [user name] -d /home/[user name] -g 1001 -N -o -u 1001
sudo passwd [user name]
```

* **-d** is the user home directory which needs to be set to /home/[user name].
* **-g** is the user group id to assign which in our example needs to be assigned to sftpgroup.
* **-N** useradd by default creates a group with the same name as the new user, this disables that.
* **-u** is the user id, which in our case needs to be the same id value as sftpgroup.
* **-o** allows duplicate, non-unique user ids.
* The **passwd** command sets an encrypted user password.

Now output the system users list to check that everything went fine:

```bash
cat /etc/passwd
```

In the last line we'll see the new added user

```bash
sftpuser:x:1001:1001::/home/sftpuser:/bin/sh
```

Now, before configuring the SSH daemon, we need to create a new keypair for this new user, in my case sftpuser, we did it before for the regular ssh connecting user (NET chapter?), so here a little refresh:

1 - Generate the new keypair on your client machine:

```bash
ssh-keygen -t rsa -b 4096 -C "raspbian_sftp_key"
```

2 - Copy the public key to the server:

```bash
ssh-copy-id -i myKey.pub sftpuser@RPI_ip_number
```

3 - That's it, exit from actual ssh session and try to log in with the new sftpuser just for testing.

**Step 6**, we need now to edit the SSH daemon configuration file, the same one we edited for SSH connection some while ago, remember? Let's do it:

```bash
nano /etc/ssh/sshd_config
```

Search for the line

```bash
Subsystem sftp /usr/lib/openssh/sftp-server
```

And change it to

```bash
#Subsystem sftp /usr/lib/openssh/sftp-server
Subsystem sftp internal-sftp
```

Now the cool part, go to the end of the document and add the following block:

```bash
Match group sftpgroup
ChrootDirectory /var/www
X11Forwarding no
AllowTcpForwarding no
ForceCommand internal-sftp
```

And this is the part where we confine the sftpgroup users group to the /var/www directory (they will not be able to escape from there, or at least they will have to sweat it).
We use /var/www because is the standard directory for web servers, but feel free to choose another folder if you prefer, like /var/sftp for example.
This step is really important, if you forget to configure the ChrootDirectory for the specific users group, a connected user could gain access to the / (the server root) and we do not actually want that!!!

So, save the document and

**Step 7**, create the /var/www folder, if you don't have it already:

```bash
mkdir /var/www
```

**Step 8**, create some testing folder, a read-only one, a read/write one and a no-access one:

```bash
cd /var/www
mkdir test_readonly
mkdir test_readwrite
mkdir test_noaccess
```

At this moment the three folders have the same permissions, let's explain a bit:

```bash
ls -la
```

Give me (we are inside /var/www):

```bash
drwxr-xr-x  5 root root 4096 Mar 26 05:41 .
drwxr-xr-x 12 root root 4096 Mar 26 05:37 ..
drwxr-xr-x  2 root root 4096 Mar 26 05:41 test_noaccess
drwxr-xr-x  2 root root 4096 Mar 26 05:40 test_readonly
drwxr-xr-x  2 root root 4096 Mar 26 05:41 test_readwrite
```

We see here a list of the folder content, just the three folders we just created, and on the left we have the permission mode:

drwxr-xr-x

Let's break it in parts:

d   

For now we will focus on the last three blocks:

rwx   r-x   r-x

The first one on the left represent the root permissions, the second one in the center represent the group permissions, and the third one on the right represent permissions for everyone else, and we can read it this way:

r w x  -->  2^2 2^1 2^0  -->  4  2  1

And in bits we can read it:

r w x --> 1 1 1

r - x --> 1 0 1

And so on

So we have some possibilities, but not so much in the end:

* 0 - No permissions
* 1 - execute permission
* 2 - write permission
* 3 - execute+write permissions
* 4 - read permission
* 5 - execute+read permissions
* 6 - read+write permissions
* 7 - execute+read+write permissions

More about Linux permissions [here](http://en.wikipedia.org/wiki/File_system_permissions#Symbolic_notation)

So, coming back to our list:

```bash
drwxr-xr-x  5 root root 4096 Mar 26 05:41 .
drwxr-xr-x 12 root root 4096 Mar 26 05:37 ..
drwxr-xr-x  2 root root 4096 Mar 26 05:41 test_noaccess
drwxr-xr-x  2 root root 4096 Mar 26 05:40 test_readonly
drwxr-xr-x  2 root root 4096 Mar 26 05:41 test_readwrite
```

We have now all the folders with 755 permissions (rwx r-x r-x), and this is ok for the test_readonly one, but we need to change the permissions for the other two:

```bash
chown root:sftpgroup test_readwrite
chmod 775 test_readwrite
```

With that we assign root as owner of the folder and sftpgroup as folder group, and with 775 permissions we grant full permission to owner, full permissions to assigned group, and execute+read permission to everyone else.

So for the noaccess folder we set permissions to 711, execute only for group and everyone else:

```bash
chmod 711 test_noaccess
```

And our list again:

```bash
drwxr-xr-x  5 root root      4096 Mar 26 05:41 .
drwxr-xr-x 12 root root      4096 Mar 26 05:37 ..
drwx--x--x  2 root root      4096 Mar 26 05:41 test_noaccess
drwxr-xr-x  2 root root      4096 Mar 26 05:40 test_readonly
drwxrwxr-x  2 root sftpgroup 4096 Mar 26 05:41 test_readwrite
```

**Step 9**, test it! We are done, restart the SSH server:

```bash
/etc/init.d/ssh restart
```

**Step 10**, connect to our SFTP server from a client, i'm using [FileZilla](https://filezilla-project.org/):

Create a new connection, with the server ip of your Raspbian server, port 22, SFTP protocol, and Key file as access type, set the name of the user, "sftpuser" in my case, and set the path to the private key from the key pair we recently create in step 5.

So, if everything was correct, we are now able to navigate our /var/www server folder from a filezilla client, great!

Next story, Apache web server install...

### Apache

A web server, this sounds like troubles! Well, it's not untrue, but here we go, let's take a step back and talk about something indispensable, the firewall, and prepare yourself, we' wi'll come back to this topic a lot, while installing all our server stuff.
A server without a good firewall set up is like a safe without a door, right now it will probably not last till the end of the day. So let's learn something about linux firewalls!

The standard debian firewall is called iptables (for IPv4, and ip6tables for IPv6) , so we'll using that, first step install it:

```bash
apt-get install iptables iptables-persistent
```

The package iptables-persistent is used to make our firewall rules persistent over reboots.

Ok, now print the current iptable rules, none right now:

```bash
iptables -L
```

My output:

```bash
Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
```

And a useful command to flush all rules (like a firewall reset):

```bash
iptables -F
```

Now, we don't want to be lock out from our server, and playing with the firewall can lock us out really easy, so first of all we add a rule that assure us to maintain untouched all current connections (basically our actual ssh connection):

```bash
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

In english, we tell to iptables to **-A** append the rule, **INPUT** to the input chain, **-m conntrack --ctstate ESTABLISHED,RELATED** relate this rule with the current connections ONLY, **-j ACCEPT** JUMP to accept and the connection are still in place.

If we list our rules again:

```bash
iptables -L
```

We'll see something new, the "door" opened for incoming current connections (our SSH connection), amazing!

Now we start to design our firewall, starting with the basics for what we already have now (SSH, SFTP and soon Apache web server), along the way we will come back and add some new rules for all the other stuff we will need on our server. Maybe it's a good idea to make yourself a new cup of coffee, or whatever you like to drink.

Let's start blocking off insecure connections, we actually are using port 22 for SSH and SFTP, and we'll want to have port 80 (http) and port 443 (https) available:

```bash
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

```bash
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

```bash
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

Now block all the remaining traffic:

```bash
iptables -P INPUT DROP
```

Allow loopback access (**-I INPUT 1** place this rule first in the list, IMPORTANT):

```bash
iptables -I INPUT 1 -i lo -j ACCEPT
```

And do not forget to permit outgoing connections (for apt-get, web browsing, sendmail, etc..)

```bash
iptables -F OUTPUT  # remove your existing OUTPUT rules if you have some
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -m state --state NEW -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -m state --state NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 25 -m state --state NEW -j ACCEPT
iptables -A OUTPUT -p tcp --sport 25 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
```

List now rules in verbose mode:

```bash
iptables -L -v
```

My output:

```bash
Chain INPUT (policy DROP 1 packets, 32 bytes)
 pkts bytes target     prot opt in     out     source               destination
    8  1104 ACCEPT     all  --  lo     any     anywhere             anywhere
 6779 9556K ACCEPT     all  --  any    any     anywhere             anywhere             state RELATED,ESTABLISHED
 1087 75053 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:ssh
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:http
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:https

Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
 3435  250K ACCEPT     all  --  any    any     anywhere             anywhere             state RELATED,ESTABLISHED
   13   780 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:http state NEW
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:https state NEW
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:domain state NEW
   21  1415 ACCEPT     udp  --  any    any     anywhere             anywhere             udp dpt:domain state NEW
```

We have now our basic firewall! Let's save it (do not change the saving files path /etc/iptables/rules.vX):

```bash
iptables-save > /etc/iptables/rules.v4 && ip6tables-save > /etc/iptables/rules.v6
```

Restart your Raspbian server and check if everything is ok, and if the rules are automatically loaded.

We are ready now to start with the Apache installation/configuration, let's do it:

```bash
apt-get install apache2
```

Now, from a client browser, let's check if it's working, copy in the url the ip of your Raspberry server and hit enter

![Apache web server](http://www.d3cod3.org/RSS/apache_screenshot.jpg)

That's it, Apache installed, and up&running! Now the configuration:

* 1 - Hide Apache version:

```bash
nano /etc/apache2/conf-enabled/security.conf
```

And add/edit this lines:

```bash
ServerSignature Off
ServerTokens Prod
```

Save and restart apache2:

```bash
/etc/init.d/apache2 restart
```

* 2 - Turn Off Directory Browsing, Disable Symbolic Links, Limit request size (to 600 Kb) and Turn Off Server Side Includes and CGI Execution

```bash
nano /etc/apache2/apache2.conf
```

Then edit the following lines:

```bash
<Directory /var/www/>
        LimitRequestBody 614400
        Options -FollowSymLinks -Includes -ExecCGI
        AllowOverride None
        Require all granted
</Directory>
```

Save and restart again.

* 3 - Disable unnecessary modules and restart again

```bash
a2dismod autoindex
a2dismod status
/etc/init.d/apach2 restart
```

* 4 - Install additional modules

```bash
apt-get install libapache2-mod-security2
```

ModSecurity need to be enabled:

```bash
mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
nano /etc/modsecurity/modsecurity.conf
```

And edit this line:

```bash
#SecRuleEngine DetectionOnly
SecRuleEngine On
```

Restart apache service and install the next module:

```bash
apt-get install libapache2-mod-evasive
```

Then append this an the end of /etc/apache2/apache2.conf:

```bash
<IfModule evasive_module>
    #optional directive (default value equals to 1024)
    DOSHashTableSize    1024

    #obligatory directives (if even one of them is not set, malfunctioning is possible)
    DOSPageCount        10
    DOSSiteCount        150
    DOSPageInterval     1
    DOSSiteInterval     1
    DOSBlockingPeriod   10
</IfModule>
```

Restart apache again, we got it! Now it's time for the newt component, the MySQL Server!

### MySQL Server

First step, install it, easy (always use strong passwords):

```bash
apt-get install mysql-server
```

And, to secure the install:

```bash
mysql_secure_installation
```

Let's test it:

```bash
mysql -u root -p
```

And you will enter the mysql console, perfect! Now install PHP!

### PHP

Now, we have a small issue here, the latest Raspbian is based on debian Jessie, that still comes with PHP 5.6 by default (from the stable branch), but we don't want an older almost unsupported (and most insecure) PHP release, we want to install PHP 7, the last release. In order to do that we'll need to tweak a little bit our apt system, let's get to it:

```bash
nano /etc/apt/sources.list
```

And add at the end:

```bash
# TWEAK - Stretch (testing) branch for PHP7 install on Jessie
deb http://mirrordirector.raspbian.org/raspbian/ stretch main contrib non-free rpi
```

Now what we don't want is that every package is updated or installed from the stretch (testing) branch. To do this we can set some preferences that we want all packages to be selected from Jessie by default. Open up the following file **/etc/apt/preferences**, and add the following:

```bash
Package: *
Pin: release n=jessie
Pin-Priority: 600
```

Save the file and update:

```bash
apt-get update
```

We have it, every time we want to install something from the testing branch, we'll do it like that (this will update the apache2 package, when asked, maintain the current config files):

```bash
apt-get install -t stretch php7.0-cli php7.0-dev php-pear libapache2-mod-php7.0 php7.0-mysql php7.0-mcrypt php7.0-sqlite3 php7.0-bcmath php7.0-bz2 php7.0-curl php7.0-gd php7.0-imap php7.0-mbstring php7.0-odbc php7.0-pgsql php7.0-soap php7.0-xml php7.0-xmlrpc php7.0-zip
```

And, to fix some issues due to this change of repo:

```bash
apt-get install -t stretch mailutils maildir-utils sendmail-bin
```

This one we'll need to wait a little longer, so we have some time to clarify something here, the moment we use the testing branch (from debian stretch), we are mixing "not yet marked stable" packages in our system, this is not a good policy for a security oriented server, but an older release of php is surely a worst case scenario, so buckle up, we just passed to the next level, little bit more challenging, feels scary but don't lie, you're liking it!

Now the last module, a specific one for [GnuPG](https://gnupg.org/) for encryption:

```bash
apt-get install -t stretch gnupg libgpg-error-dev libassuan-dev
```

Go to a temp folder and download gpgme library:

```bash
wget https://www.gnupg.org/ftp/gcrypt/gpgme/gpgme-1.8.0.tar.bz2
```

Extract, configure, make && make install:

```bash
tar xvfj gpgme-1.8.0.tar.bz2 && cd gpgme-1.8.0 && ./configure
```

Then

```bash
make && make install
```

and

```bash
pecl install gnupg
```

last one, open /etc/php/7.0/apache2/conf.d/20-gnupg.ini

```bash
nano /etc/php/7.0/apache2/conf.d/20-gnupg.ini
```

and add the following line:

```bash
extension=gnupg.so
```

Save & close the file, and to fix a little library loading issue, open this new file:

```bash
nano /etc/ld.so.conf.d/userlib.conf
```

then add this line:

```bash
/usr/local/lib
```

Save/close the file, and rerun ldconfig to rebuild the cache:

```bash
ldconfig
```

Finally restart apache, and create a new file for print php info:

```bash
nano /var/www/html/info.php
```

Then add the following typical php code:

```bash
<?php phpinfo(); ?>
```

Now open from your client browser the following url: http://your_raspbian_server_ip/info.php, if everything went fine you will see the common php information page.

![PHP Install](http://www.d3cod3.org/RSS/php_install.jpg)

We are done with PHP installation, now we remove the info file for security reasons:

```bash
rm -i /var/www/html/info.php
```

This is starting to look nice!

Ok, let's hit pause for a moment, and take a better look at what we have at the moment:

```bash
service --status-all
```

This command will give us the complete list of services available on our server, where [ + ] means service started, [ - ] service stopped, and [ ? ] state unknown.

But let's take a deep look with another program:

```bash
apt-get install chkconfig
```

and

```bash
chkconfig --list
```

This will show us the availability of our services at all different runlevels. No room here for a runlevel class, so [here](https://en.wikipedia.org/wiki/Runlevel) some more info.

And another really powerful tool for discovering services is the systemd init system:

```bash
systemctl list-units -t service
```

And as we did before with netstat, let's check all active tcp connections:

```bash
netstat -atp
```

My output:

```bash
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 localhost:smtp          *:*                     LISTEN      1151/exim4
tcp        0      0 192.168.1.104:22        *:*                     LISTEN      310/sshd
tcp        0      0 localhost:mysql         *:*                     LISTEN      781/mysqld
tcp        0     92 raspbian.ip.number:22   client.ip.number:port   ESTABLISHED 1188/sshd: username
tcp6       0      0 localhost:smtp          [::]:*                  LISTEN      1151/exim4
tcp6       0      0 [::]:http               [::]:*                  LISTEN      736/apache2
```

As you can see, we have our newly installed apache2 and mysql services listening, our active ssh connection established, and a new one, the exim4 service listening too, but hey, we do not install this exim4, what is that? Well, when we installed php7, one of his dependencies is the exim4 service for sending system information to internal users, so the system installed it automatically.

So here we are, our server is starting to get all the pieces in place. Next story? Hide our SSH service!

## Hide

This is the last last layer of security we are going to add to our SSH and SFTP services, it is some kind of advanced obfuscation technique, so not everyone will agree that it is really useful, but hey, in my opinion it can add some trouble for an attacker trying to own our server, so here we go, let's install a port knocker!
And what is a port knocker? Is a special type of disguised service that listen for a specific sequence of "knocks" on a predefined list of ports, when this list of port is correctly "knocked" this service opens temporarily a specified port (our enter door to the server, the SSH port 22) in order to obtain access, and close it again after we log in.
It's the same as knocking at your house door with a predefined knocking code, then someone open the door, and close it again after you are inside.
So, in terms of visibility (port scanning for example), our server will be invisible, because at the question: is the SSH port listening?, the answer will be NO.

But BEWARE! Port Knocking techniques are an open debate about actual efficiency and if we can really gain some more security with it, so search the internet and read about it, then choose if you want that on your server, or not.

### Port Knock

Let's get to it, install the debian standard port knocker:

```bash
apt-get install knockd
```

Then edit his main config file, /etc/knockd.conf, you will have something like this:

```bash
[options]
        UseSyslog

[openSSH]
       sequence    = 7000,8000,9000
       seq_timeout = 5
       command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
       tcpflags    = syn

[closeSSH]
       sequence    = 9000,8000,7000
       seq_timeout = 5
       command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
       tcpflags    = syn
```

And change it to something like this:

```bash
[options]
        UseSyslog

#[openSSH]
#       sequence    = 7000,8000,9000
#       seq_timeout = 10
#       command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
#       tcpflags    = syn

#[closeSSH]
#       sequence    = 9000,8000,7000
#       seq_timeout = 10
#       command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
#       tcpflags    = syn

[SSH]
        sequence        = 5004,1233,8732,1112,6
        seq_timeout     = 10
        cmd_timeout     = 15
        start_command   = /sbin/iptables -I INPUT 1 -s %IP% -p tcp --dport 22 -j ACCEPT
        stop_command    = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
        tcpflags        = syn
```

Let's see, we commented out the [openSSH] and [closeSSH] blocks, and added a new block called [SSH], this is because we want to automatically close the port 22 some seconds after we opened it, we do not want to have different knocking sequences for first open and then later close the port.
In our new [SSH] block we configured the port knocking sequence with a random port sequence (i've used 5004,1233,8732,1112,6, you choose yours), the time for receiving the knocks (seq_timeout), the time the system wait to close the port after the opening (cmd_timeout), then the command for open the port (start_command, an iptables rule that momentarily give us access to the port), and finally the closing command (stop_command).

Ok, so now edit another file, /etc/default/knockd and make it look like this:

```bash
################################################
#
# knockd's default file, for generic sys config
#
################################################

# control if we start knockd at init or not
# 1 = start
# anything else = don't start
#
# PLEASE EDIT /etc/knockd.conf BEFORE ENABLING
START_KNOCKD=1

# command line options
KNOCKD_OPTS="-i eth0"
```

That's it, restart the knockd service and test it:

```bash
/etc/init.d/knockd restart
```

Now, before we finish to configure the firewall and hide our SSH service, we have to make sure this is working, because is we do not configure it properly, or something go wrong, we will be closed out by our server!!! The firewall will close the port 22, and we will need to access directly to the server to fix the issue (not a problem if your server is in your room, a little worst if the server is elsewhere...)
So, let's test it!

**From a client machine**, create the following script:

```bash
#!/bin/bash

for x in 5004,1233,8732,1112,6;
do nmap -Pn --host_timeout 201 --max-retries 0 -p $x your.rpi.server.number;
done
```

Change the port sequence accordingly and the server IP, and save it the script as knock_rpi.sh

If you don't have nmap installed in your client, install it, [nmap](https://nmap.org/)

The moment of truth, run from a terminal in your client:

```bash
sh knock_rpi.sh
```

Then in your server print the iptables rules:

```bash
iptables -L -v
```

If everything went right, you will see something similar to this line at the beginning of the INPUT chain:

```bash
27  1872 ACCEPT     tcp  --  any    any     your.client.ip.number        anywhere             tcp dpt:ssh
```

That's it, this is the line tha knockd temporarily add to the firewall in order to let us in via port 22.

If we print the iptables rules again, this rule had disappeared because knockd command will timeout, so server hidden again.

Ok, last step, we need to delete from our firewall the rule we configured before about listening at port 22, remember? :

```bash
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

In order to do that we open the file /etc/iptables/rules.v4:

```bash
nano /etc/iptables/rules.v4
```

And remove this line:

```bash
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
```

This is it! Restart our server and try it!

```bash
shutdown -r now
```

Now, if we try to connect via SSH like always, the server will not respond, because the port 22 is actually closed! In order to SSH into our server we need to "knock" before, and then ask for a ssh connection.

So:

```bash
sh knock_rpi.sh
```

Then later (like always):

```bash
ssh -i ~/.ssh/your_rsa_key_name -p 22 username@RPi_ip_number
```

And that's it, SSH service well hidden!

This will be the same for SFTP connection, "knock" before ask for connection!

Well, we have done most of the job, we almost have our secure server, we just need to secure something more, then configure our domain DNS, configure our local router, and finally start using it.
But don't rush, one step at the time, next story, "Fingerprint Your Files"

## Security

Let's say it, this was not so difficult in the end, we are now reaching the end of our journey, and this doesn't mean we looked at everything nor that we are now good sysadmin security experts, nothing more far from the truth actually, this field is an incredibly complex one, especially for online servers, it needs dedication, continuos update (on personal side as on machine side), imagination and a lot of hours of practice, really a lot!
So, we are not experts yet, but maybe some of us will be one day, who knows. In the meantime, let's finish our basic security configuration for our Raspbian personal server, intrusion detection systems, here we go.

### RKHunter

RKHunter is a [rootkit](https://en.wikipedia.org/wiki/Rootkit) protection system. Rootkits are an extremely dangerous problems for online servers, once secretly installed on servers, they permit intruders to repeatedly enter the server without been detected. In short, if a server have a unresolved vulnerability, some attacker could use it to install a rootkit, then imagine that the sysadmin of the server fix the vulnerability, the server is now secure! but the invisible rootkit is already there, so the attacker can come back whenever he/she want, through the rootkit that was installed.

So, it's a good idea to install RKhunter, it will help us to protect our system from this kinds of problems, let's do it:

```bash
apt-get install -t stretch libwww-perl
```

We need to install it from the testing repo because some dependencies of rkhunter was previously installed by the php installation.

```bash
apt-get install -t stretch rkhunter
```

This will install the rkhunter 1.4.2, let's check it:

```bash
rkhunter --versioncheck
```

Ok, now we perform an update of our data files, some kind of "base" information about our filesystem that rkhunter will use for checks:

```bash
rkhunter --update
```

Now we confir to rkhunter that this is the baseline from which to do the checks:

```bash
rkhunter --propupd
```

Perfect, we are ready to perform our initial run, this will probably produce some warnings, but don't worry, this is expected:

```bash
rkhunter -c --enable all --disable none
```

This will take his time, and will ask to press enter for execute different checks.

Ok, log saved, open it and review:

```bash
nano /var/log/rkhunter.log
```

Then search for "Warning", i have the following:

```bash
...
Warning: Found preloaded shared library: /usr/lib/arm-linux-gnueabihf/libarmmem.so
...
Warning: The command '/sbin/chkconfig' has been replaced by a script: /sbin/chkconfig: Perl script, ASCII text executable
...
Warning: The following processes are using deleted files:
Process: /usr/sbin/apache2    PID: 673    File: /tmp/.ZendSem.BwxJJJ
Process: /usr/sbin/mysqld    PID: 794    File: /tmp/ibI3FUpC
Process: /usr/sbin/apache2    PID: 3078    File: /tmp/.ZendSem.BwxJJJ
Process: /usr/sbin/apache2    PID: 3079    File: /tmp/.ZendSem.BwxJJJ
Process: /usr/sbin/apache2    PID: 3080    File: /tmp/.ZendSem.BwxJJJ
Process: /usr/sbin/apache2    PID: 3081    File: /tmp/.ZendSem.BwxJJJ
Process: /usr/sbin/apache2    PID: 3082    File: /tmp/.ZendSem.BwxJJJ
...
Warning: Process '/usr/sbin/knockd' (PID 366) is listening on the network.
...
```

Another way to perform a complete check printing warning only is:

```bash
rkhunter -c --enable all --disable none --rwo
```

We have now a simple example of rkhunter warning, let's configure it a little:

```bash
nano /etc/rkhunter.conf
```

First, we set up local mail for receiving notification when rkhunter hits a warning:

```bash
MAIL-ON-WARNING=root@localhost
MAIL_CMD=mail -s "[rkhunter] Warnings found for ${HOST_NAME}"
```

Then we'll fix the warnings that told us that some binary packages have been replaced by scripts:

```bash
SCRIPTWHITELIST=/sbin/chkconfig
```

Next, allow apache2 and mysqld process to use deleted files, this is not ALWAYS the better thing to do, but in our case, we have a clean box, no one has touched our server (at least in my case) apart from me, and we haven't open it to the internet yet, so, it is not crazy to consider this a false positive, in which case i decided to whitelist it:

```bash
ALLOWPROCDELFILE=/usr/sbin/apache2
ALLOWPROCDELFILE=/usr/sbin/mysqld
```

Next, we whitelist a specific rpi arm preloaded shared library that is giving us another false positive:

```bash
SHARED_LIB_WHITELIST=/usr/lib/arm-linux-gnueabihf/libarmmem.so
```

And finally, the last one (in my case), we have knockd installed and listening to the network interface (our port knocker), so we need to whitelist it:

```bash
ALLOWPROCLISTEN=/usr/sbin/knockd
```

Ok, we check the configuration for errors:

```bash
rkhunter -C
```

If no errors, then we re-run a check again:

```bash
rkhunter -c --enable all --disable none --rwo
```

RKHunter will tell us here that the rkhunter.conf file properties has changed, fine, so we update his db (set a new baseline):

```bash
rkhunter --propupd
```

That's it, we are ready for the last step, automate the checks with a [CRON job](https://en.wikipedia.org/wiki/Cron):

```bash
crontab -e
```

This will open our crontab file for edit, here we will add a line that will tell the system to run an rkhunter check every day at the specified time:

```bash
25 05 * * * /usr/bin/rkhunter --cronjob --update --quiet
```

In this line we are telling cron to launch rkhunter check at 05:25am every day, and as configured, if it finds some warnings, we'll receive an email at the specified mail with the details.

We have it! RKHunter ready and running checks every day, amazing! But remember, you'll need to check regularly for messages about warnings, at least once a week, in order to keep everything in order, every new change in the system could be recognized as a warning by rkhunter, so we'll need to always take a look a keep it clean from false positives, if we want to be able in the future to recognize real bad files.

Perfect, we'll now install and configure a network intrusion detection, next story PSAD!

### psad Network Intrusion Detection System

**psad** stands for port scan attack detection, and is a software that monitors firewall logs to determine is a scan/attack is in progress. It can alert system administrators, like rkhunter via mail, or it can take active steps to deter the threat.

As always, let's install it:

```bash
apt-get install -t stretch psad
```

Now the firewall config, let's add the necessary rules to our firewall (iptables) to let psad do the work:

```bash
iptables -A INPUT -j LOG && iptables -A FORWARD -j LOG
```

That's it, this was super easy!

Now it's the config time, open the psad config file:

```bash
nano /etc/psad/psad.conf
```

And start by configuring the scans detection, search and change the following:

```bash
HOSTNAME    pi; # or whatever hostname you set on your raspbian server, if you don't know it, use the "hostname" command
IPT_SYSLOG_FILE         /var/log/syslog;
IGNORE_PORTS            your_port_knocking_ports;
ENABLE_PERSISTENCE          N;
MAX_SCAN_IP_PAIRS           50000;
MIN_DANGER_LEVEL            3;
EMAIL_ALERT_DANGER_LEVEL    4;
```

Now implement intrusion detection, but first update psad signature definitions and restart the service:

```bash
psad --sig-update && /etc/init.d/psad restart
```

But before implement the intrusion detection, let's play a little, we are going to do a port scan!!!
From a client run this on a terminal:

```bash
sudo nmap -PN -sS your_rpi_server_ip
```

Then wait for finish or stop it after a while, then run on server:

```bash
psad -S
```

AHHHHHHHHHH! Don't worry, it was you with your port scan doing all that. This is the current status of psad service, cool eh? A lot of info about our server network!
Very good, now it's time to edit some more config:

```bash
nano /etc/psad/auto_dl
```

Then add:

```bash
127.0.0.1       0;
your.local.machine.ip   0; # local machine
```

This will exempt those ip numbers from psad intrusion detection system, good so we don't ever end locked out from our server.

Now go back to the psad main config file /etc/psad/psad.conf end edit the following:

```bash
ENABLE_AUTO_IDS         Y;
AUTO_IDS_DANGER_LEVEL       4;
AUTO_BLOCK_TIMEOUT          3600;
```

This will enable the auto firewall configuration, banning a specific ip for 60 minutes if detected a danger level 4 (a normal SYN scan for example), we got it!

It's testing time, from another client connected to your local network, not from the one where you have the current SSH connection open, run this command:

```bash
sudo nmap -PN -sS your_rpi_server_ip
```

In the meantime, close your ssh connection and reconnect, then on your server show the actual iptables rules:

```bash
iptables -S
```

My output:

```bash
...
N PSAD_BLOCK_FORWARD
-N PSAD_BLOCK_INPUT
-N PSAD_BLOCK_OUTPUT
...
-A PSAD_BLOCK_FORWARD -d the.scanning.client.ip/32 -j DROP
-A PSAD_BLOCK_FORWARD -s the.scanning.client.ip/32 -j DROP
-A PSAD_BLOCK_INPUT -s the.scanning.client.ip/32 -j DROP
-A PSAD_BLOCK_OUTPUT -d the.scanning.client.ip/32 -j DROP
...
```

As you can see psad added a new chain with new rules to our firewall, and the scanning ip number is banned now!!! YHEAAAAAAAA! It's working!

Now we'll couple **psad** with **tripwire**, and our Intrusion Detection System will become fairly good, but this is the next story.

### Tripwire Intrusion Detection System

Tripwire is host-based intrusion detection system (HIDS), it collects details about our filesystem and configurations.

First, install:

```bash
apt-get install tripwire
```

Answer yes to everything and set the passwords it asks.

Then, similar as rkhunter, initialize the tripwire database:

```bash
tripwire --init
```

And we run a check saving the result into a file:

```bash
cd /etc/tripwire
sh -c 'tripwire --check | grep Filename > test_results'
```

We have now a starting list of tripwire complains, let's configure it good to match our system:

```bash
nano /etc/tripwire/twpol.txt
```

In the "Boot Scripts" section we comment the /etc/rc.boot line, since this isn't present in our raspbian system:

```bash
#        /etc/rc.boot            -> $(SEC_BIN) ;
```

And the same for the "Root config files" section, comment all the lines from your test_results file. In my case:

```bash
/root                           -> $(SEC_CRIT) ; # Catch all additions to /root
        /root/mail                      -> $(SEC_CONFIG) ;
        #/root/Mail                     -> $(SEC_CONFIG) ;
        #/root/.xsession-errors         -> $(SEC_CONFIG) ;
        #/root/.xauth                   -> $(SEC_CONFIG) ;
        #/root/.tcshrc                  -> $(SEC_CONFIG) ;
        #/root/.sawfish                 -> $(SEC_CONFIG) ;
        #/root/.pinerc                  -> $(SEC_CONFIG) ;
        #/root/.mc                      -> $(SEC_CONFIG) ;
        #/root/.gnome_private           -> $(SEC_CONFIG) ;
        #/root/.gnome-desktop           -> $(SEC_CONFIG) ;
        #/root/.gnome                   -> $(SEC_CONFIG) ;
        #/root/.esd_auth                        -> $(SEC_CONFIG) ;
        #/root/.elm                     -> $(SEC_CONFIG) ;
        #/root/.cshrc                   -> $(SEC_CONFIG) ;
        /root/.bashrc                   -> $(SEC_CONFIG) ;
        /root/.bash_profile            -> $(SEC_CONFIG) ;
        /root/.bash_logout             -> $(SEC_CONFIG) ;
        /root/.bash_history             -> $(SEC_CONFIG) ;
        #/root/.amandahosts             -> $(SEC_CONFIG) ;
        #/root/.addressbook.lu          -> $(SEC_CONFIG) ;
        #/root/.addressbook             -> $(SEC_CONFIG) ;
        #/root/.Xresources              -> $(SEC_CONFIG) ;
        #/root/.Xauthority              -> $(SEC_CONFIG) -i ; # Changes Inode number on login
        #/root/.ICEauthority                -> $(SEC_CONFIG) ;
```

Almost done, we had some complains about some files descriptors inside /proc filesystem, and this files changes all the time, so in order to avoid regular false positives, we'll remove the specific check over the general /proc folder and we'll add all directories under /proc that we want to check.
Go to the "Devices & Kernel information" section and make it look like this:

```bash
        /dev            -> $(Device) ;
        /dev/pts        -> $(Device) ;
        #/proc          -> $(Device) ;
        /proc/devices           -> $(Device) ;
        /proc/net               -> $(Device) ;
        /proc/tty               -> $(Device) ;
        /proc/sys               -> $(Device) ;
        /proc/cpuinfo           -> $(Device) ;
        /proc/modules           -> $(Device) ;
        /proc/mounts            -> $(Device) ;
        /proc/filesystems       -> $(Device) ;
        /proc/interrupts        -> $(Device) ;
        /proc/ioports           -> $(Device) ;
        /proc/self              -> $(Device) ;
        /proc/kmsg              -> $(Device) ;
        /proc/stat              -> $(Device) ;
        /proc/loadavg           -> $(Device) ;
        /proc/uptime            -> $(Device) ;
        /proc/locks             -> $(Device) ;
        /proc/meminfo           -> $(Device) ;
        /proc/misc              -> $(Device) ;
```

And the last one, we need to comment out the /var/run and /var/lock lines so that our system does not flag normal filesystem changes by services:

```bash
        #/var/lock              -> $(SEC_CONFIG) ;
        #/var/run               -> $(SEC_CONFIG) ; # daemon PIDs
        /var/log                -> $(SEC_CONFIG) ;
```

DONE! With tripwire configured, first we recreate his encrypted policy:

```bash
twadmin -m P /etc/tripwire/twpol.txt
```

and reinitialize the database:

```bash
tripwire --init
```

If everything went right, we we'll have no warnings, so run a check:

```bash
tripwire --check
```

There we go, this will be a typical tripwire report.

Let's clean the system from sensitive information:

```bash
rm /etc/tripwire/test_results
rm /etc/tripwire/twpol.txt
```

Just in case we someday need to edit again the tripwire config, we'll need to temporarily recreate the plaintext file we just edited:

```bash
sh -c 'twadmin --print-polfile > /etc/tripwire/twpol.txt'
```

This is how we do it!

Right, we are near the end of the story, we only need to set up tripwire email notification and automate checks with CRON, like we did it for rkhunter, let's get to it:

```bash
tripwire --check | mail -s "Tripwire report for `uname -n`" your@email
```

This will generate a tripwire report and send it to the specified mail. Just like that!

What next then, well we add a new cron job to our cron table:

```bash
crontab -e
```

and we add this line:

```bash
30 03 * * * /usr/sbin/tripwire --check | mail -s "Tripwire report for `uname -n`" your@email
```

So, every day we will receive a report from our **tripwire** system, and another one from **rkhunter** in case it find some warnings.

We are set and decently secured, we are at the last steps of our journey, we'll just need to secure apache with a TLS/SSL certificate from Let's Encrypt, then set up our hostnames we are going to host, and finally, correctly and securely configure our home router to have our amazing Raspbian Server available on the internet!!!!

Next story, TLS/SSL certificates.

### TLS/SSL

SSL certificates are used within web servers to encrypt the traffic between the server and client, providing extra security for users accessing your application. Let's Encrypt provides an easy way to obtain and install trusted certificates for free.

Remember that in order to complete this step, you need to have already configured some domain (www.yourdomain.com) with DNS pointing to your home server (your home IP address).

So we are going to install and configure our apache server with a TLS/SSL certificate from [Let's Encrypt](https://letsencrypt.org/), let's do it:

```bash
apt-get install augeas-lenses libaugeas0
apt-get install -t stretch python-certbot-apache
```

Now set up the SSL certificate:

```bash
certbot --apache
```

This will be really straightforward, the certbot mechanism will do all the work, answer his questions and you will have it!

Now try to connect to https://www.yourdomain.whatever and that's it, SSL certificate up and running.

Now, let's encrypt certificates needs to be renewed every 90 days, so the best is to automatize the check for renewal with a cronjob, open your crontab:

```bash
crontab -e
```

and add this line (customize the time at your wish):

```bash
00 4 * * 1 /usr/bin/certbot renew >> /var/log/le-renewal.log
```

That line means check, every monday at 04:00h if we need to renew our let's encrypt certificates, and if that's the case, renew them. Easy!

We have it, our server is almost complete, next story, HARDENING!

## HARDENING (BONUS)

Kernel hardening and IPv6 disable, edit file /etc/sysctl.conf and add/edit:

```bash
# Turn on execshield
kernel.exec-shield=1
kernel.randomize_va_space=1
...
#Uncomment the next two lines to enable Spoof protection (reverse-path filter)
# Turn on Source Address Verification in all interfaces to
# prevent some spoofing attacks
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
...
# Do not send ICMP redirects (we are not a router)
net.ipv4.conf.all.send_redirects = 0
#
# Do not accept IP source route packets (we are not a router)
net.ipv4.conf.all.accept_source_route = 0
#net.ipv6.conf.all.accept_source_route = 0
#
# Log Martian Packets
net.ipv4.conf.all.log_martians = 1
...
# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.eth0.disable_ipv6 = 1
```

Now open file /etc/default/ntp and make it look like this:

```bash
NTPD_OPTS='-4 -g'
```

Reboot and enjoy!

## HOME ROUTER SETTINGS

In order to be available on the internet, we'll need to open the specific ports for the specific services we want to offer to users, so, at home we have our fantastic Raspbian Server connected to the internet BEHIND our router, and even if the server is perfectly configured with his firewall, the router is, by default, completely closed for input connections, with the consequence of not letting no one reach our webpage on port 80 (http) or port 443 (https) because when we'll ask for it, our router will deny the access. This is actually good, if our router was completely open, probably our internet connection will be flooded in no time!

So, remember here that, for every port you'll open on your router, that means availability but exposure too, and it's because of it that we are trying to build a pretty secure server.

Enough chat, in short we'll need to access our router settings, in general at ip 192.168.1.1 (but now always, check your router user manual), and in the firewall section, or in the port forwarding section (it depends on the router model), we'll need to open the port for our specific server, for example, if we want to run a web server, we'll need to forward port 80 to port 80 of our Raspbian (pointing to the internal LAN server ip), and the same for port 443.
Or, if we want to access via SSH from internet, we'll need to forward input port 22 to port 22 of the server internal LAN ip.

The same for every other service you'll need.

So do it, and then test your services, if everything was correct, your server is actually AVAILABLE!!! Congratulation!

## Your 80€ dedicated server (80DS)
