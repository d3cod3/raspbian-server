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

So we have some possibilities, but not so much in the end:  0, 1, 2, 3, 4, 5, 6, 7

The detailed list is:

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

## Security

### Firewall

### Fail2Ban

### IDS (Intrusion Detection System)

## Hardening

## Hide

## Attack (Testing)

## Your 50€ dedicated server (50DS)
