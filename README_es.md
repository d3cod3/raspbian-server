# Raspbian Secure Server Config Tutorial (R.S.S.C.T)

Tabla de contenidos
=================

   * [Descripción](#descripción)
   * [Instalación](#instalación)
   * [Configuración Post-Instalación](#configuración-post-instalación)
   * [Configuración](#configuración)
      * [Usuarios](#usuarios)
         * [SSH](#ssh)
         * [Fail2ban (Sección Especial)](#fail2ban-sección-especial)
      * [Net](#net)
      * [DNS](#dns)
      * [Servicios](#servicios)
         * [SFTP](#sftp)
         * [Apache](#apache)
         * [MySQL Server](#mysql-server)
         * [PHP](#php)
         * [Ruby on Rails con rbenv (EXTRA BONUS - NIVEL INTERMEDIO!!!!)](#ruby-on-rails-with-rbenv-extra-bonus---intermediate-level)
      * [Hide](#hide)
         * [Port Knock](#port-knock)
      * [Securidad](#securidad)
         * [RKHunter](#rkhunter)
         * [psad Network Intrusion Detection System](#psad-network-intrusion-detection-system)
         * [Tripwire Intrusion Detection System](#tripwire-intrusion-detection-system)
         * [Logwatch Log Analyzer](#logwatch-log-analyzer")
         * [TLS/SSL](#tlsssl)
      * [HARDENING (BONUS)](#hardening-bonus)
      * [CONFIGURACIÓN ROUTER CASERO](#home-router-settings)
      * [Tu servidor dedicado de 80€ (80DS)](#tu-servidor-dedicado-de-80-80ds)

# Descripción

Vamos a construir un servidor en casa con una RaspberryPI, utilizando un sistema operativo [Raspbian](https://www.raspbian.org/) OS,mínimo optimizado, configurarlo, asegurarlo, ocultarlo, probarlo y, por supuesto, disfrutarlo!

Este tutorial es para Raspberry Pi Modelo 1B, 1B+ y 2B, con una pequeña tarjeta microSD de 8GB (estoy utilizando una de 95mb/s 64GB) y el estandard RPi de 1GB de memoria RAM.

_Para los modelos RPi 3 o RPi zero, puede hacerse con [alpha branch v1.1.x de raspbian-ua-netinst](https://github.com/debian-pi/raspbian-ua-netinst/tree/v1.1.x), pero ten cuidado, algunas cosas de este tutorial serán probablemente diferentes, y podrás resolverlas solo con mucha pasión y entusiasmo._

Aquí se detalla el proceso de la construcción del servidor, ¡vamos a hacer un café y con_seguirlo!


# Instalación

Lo primero fue buscar una versión mínima de Raspbian, algo similar a la versión [netinst de Debian](https://www.debian.org/CD/netinst/), así que busqué en la web (no con google,
prefiero usar [DuckDuckGo](https://duckduckgo.com/) porque no te rastrea, o al menos así parece) y encontré una gran contribución del usuario de guithub [debian-pi](https://github.com/debian-pi), el repositorio [raspbian-ua-netinst](https://github.com/debian-pi/raspbian-ua-netinst), un Raspbian (mínimo) que se instala a través de la red!

¡Asombroso!

Por eso vamos a seguir las instrucciones del repositorio; descargar la última versión del instalador y cargarla en la tarjeta SD. Fácil.

El segundo paso es poner la tarjeta SD con el instalador en tu RPi, encender y esperar, el instalador arrancará la RPi, y se conectará a Internet (es necesario conectar la RPi con un cable ethernet), descargando la última versión de Raspbian, e instalándola.
Dependiendo de tu velocidad de conexión tendrás que ir a por otro café, o no.

Cuando termine este paso, tendrás un sistema Raspbian mínimo, con ssh habilitado por defecto, el usuario root con contraseña: raspbian, y todas las herramientas básicas de línea de comandos necesarias. (Puedes consultar los detalles en el repositorio  [raspbian-ua-netinst](https://github.com/debian-pi/raspbian-ua-netinst))

Si todo ha ido bien, ahora puedes comunicar con tu RPi a través de ssh con {user: root, password: raspbian}:

```bash
ssh root@RPI_ip_number
```

Vamos a imprimir alguna información sobre el sistema, primero la versión del kernel que está funcionando:

```bash
cat /proc/version
```
mi respuesta es:

```bash
Linux version 4.4.0-1-rpi2 (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Raspbian 4.9.2-10) ) #1 SMP Debian 4.4.6-1+rpi14 (2016-05-05)
```
La distribución y versión de Linux:

```bash
cat /etc/*release*
```

mi respuesta:

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

El bloque de dispositivos:

```bash
lsblk
```
mi respuesta (con tarjeta SD 64GB):

```bash
NAME        MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
mmcblk0     179:0    0  59.5G  0 disk
├─mmcblk0p1 179:1    0 122.1M  0 part /boot
└─mmcblk0p2 179:2    0  59.4G  0 part /
```

o expresado de una forma más legible:

```bash
df -h --output=source,fstype,size,pcent,target -x tmpfs -x devtmpfs
```

¡Este es solo el comienzo! En la siguiente sesión haremos una pequeña configuración posterior a la instalación, solo las sugerencias de [raspbian-ua-netinst](https://github.com/debian-pi/raspbian-ua-netinst), siguiente historia: "Post-Install Config".

# Configuración Post-Instalación

1 - Poner un nuevo password para root:

```bash
passwd
```

2 - Designar tu configuración regional

```bash
dpkg-reconfigure locales
```

3 - Configurar tu zona horaria

```bash
dpkg-reconfigure tzdata
```

4 - Mejorar el rendimiento de la gestión de memoria

```bash
apt-get install raspi-copies-and-fills
```

5 - Instalar, cargar automáticamente y usar el módulo del kernel para el generador de números aleatorios del hardware. Esto mejora el rendimiento de varias aplicaciones del servidor que necesitan números aleatorios significativamente.

```bash
apt-get install rng-tools
```

6 - Crear un archivo SWAP de 1 GB y habilítalo en el arranque modificando el archivo fstab:

```bash
dd if=/dev/zero of=/swap bs=1M count=1024 && mkswap /swap && chmod 600 /swap
echo "/swap none swap sw 0 0" | tee -a /etc/fstab
```

Ok, ya tenemos lo básico de la post-instalación para nuestro servidor Raspbian!

En este momento siento curiosidad por cosas como [Attack Surface](https://en.wikipedia.org/wiki/Attack_surface), podemos imprimir alguna información:

```bash
find / -perm -4000 -print
```

Este comando nos devuelve los potenciales puntos vulnerables del sistema, listando todos los archivos ejecutables con [SUID](https://en.wikipedia.org/wiki/Setuid). En mi caso:

```bash
/bin/mount
/bin/umount
/bin/su
```

Básicamente, SUID (Set User ID) son permisos de acceso que pueden asignarse a archivos y permiten a un usuario activar un ejecutable con el permiso de administrador, por lo que si alguien encuentra una vulnerabilidad en uno de estos programas y lo activa, GAME OVER, tendrá permisos a nivel de root en el sistema, y adiós a la seguridad del servidor Raspbian!!!   

Pero no te preocupes, sólo estamos empezando, un largo viaje nos espera, con mucho que aprender.


Vamos a instalar y configurar todos los elementos esenciales para nuestro Raspbian Secure Server, próxima historia, "Configuración".


# Configuración

En primer lugar, vamos a instalar algunos paquetes de descarga con utilidades:

```bash
apt-get install apt-utils
```

Es importante sentirnos cómodos al editar un montón de archivos de texto, tal vez algunos de programación también :P, así que empezamos instalando nuestro editor de texto de consola favorito, voy a usar "nano", pero hay otras opciones, tal vez mejores, como "vim". Escoge aquí la que más te convenga:


```bash
apt-get install nano
```

Y lo customizamos, abriendo el archivo nanorc con el propio nano:

```bash
nano /etc/nanorc
```

Y eliminamos el comentario # set const para añadirle la numeración de líneas:

```bash
# set const
set const
```

## Users

Antes que nada, necesitamos instalar **sudo**, un programa que permite a los usuarios normales ejecutar algunos comandos como root, y ¿por qué hacemos esto? Porque es más seguro que abrir siempre las sesiones con root, nadie necesitará saber la contraseña de root, cada ejecución se registrará sucesivamente y aportará  una mayor seguridad.

```bash
apt-get install sudo
```
Crear un nuevo usuario que tenga una cuenta con privilegios normales (cambiar "user" por el nombre elegido):

```bash
adduser user
```

Seguir las instrucciones rellenando todos los campos que quieras, y lo más importante, poner una contraseña segura.

Ahora necesitamos añadir al nuevo usuario a un grupo de sudo, para concederle las capacidades de sudo:

```bash
adduser user sudo
```

Mi respuesta:

```bash
Adding user 'user' to group 'sudo'
Adding user user to group sudo
Done.
```
Para aplicar la nueva asignación de grupo, desconectarse e iniciar sesión con el nuevo usuario

Siguiente historia, SSH

### SSH

Crear un nuevo par de claves SSH para proteger el servidor con una autentificación de clave pública para el nuevo usuario:

1 - **En tu ordenador local**, genera un par de claves:

```bash
ssh-keygen -t rsa -b 4096 -C "raspbian_rsa"
```
Elegir el nombre del archivo de la clave (Ej: myKey) y poner un password
Con esto se genera una clave privada, "myKey", y una clave pública "myKey.pub", en la carpeta .ssh del directorio home del usuario local. Recuerda que no debes compartir la clave privada con nadie que no deba tener acceso a tu servidor!

2 - **En tu ordenador local**, copia la clave pública al servidor:

```bash
ssh-copy-id -i myKey.pub user@RPI_ip_number
```

Eso es todo, ahora podemos acceder al servidor desde nuestro ordenador local, a través de SSH, utilizando la clave privada como autentificación, por lo que ha llegado el momento de configurar nuestro daemon SSH para una mejor seguridad.


Abrimos el archivo de configuración de SSH

```bash
nano /etc/ssh/sshd_config
```

Y cambiamos:

0 - Deshabilitar ipv6:

```bash
#ListenAddress ::
ListenAddress 0.0.0.0
```

1 - Rechazar el acceso SSH a la cuenta root:

```bash
PermitRootLogin no
```

2 - Disable X11Forwarding:

```bash
X11Forwarding no
```

3 - Añadimos AllowUsers user, para permitir el acceso al nuevo usuario SOLAMENTE:

```bash
AllowUsers user
```

4 - Deshabilitar la autenticación de contraseña de texto sintonizado y habilitar el acceso solo de clave pública SSH

```bash
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile      %h/.ssh/authorized_keys
```

5 - Guardar el archivo (ctrl o), cerrarlo (ctrl x) y reiniciar el servicio SSH:

```bash
/etc/init.d/ssh restart
```

6 - **En tu ordenador local**, desconecta, y comprueba el login SSH, que ahora solo se hará con tu clave generada, por que el password de texto normal está ahora deshabilitado.

```bash
ssh -i ~/.ssh/your_rsa_key_name -p 22 username@RPi_ip_number
```
Para los más curiosos, -i especifica el archivo identity_file (tu clave privada del par de claves), y -p especifica el puerto al que conectarse (22 es el puerto ssh estándar).


7 - Para más información sobre servicios de seguridad, echa un vistazo al [debian manual](https://www.debian.org/doc/manuals/securing-debian-howto/ch-sec-services.en.html)

Ahora aseguraremos más nuestra conexión SSH para protegerlo contra [brute force attacks](https://en.wikipedia.org/wiki/Brute-force_attack). Instalando **fail2ban**

### Fail2ban (Sección Especial)

Fail2ban proporciona una forma de proteger automáticamente los servidores virtuales contra el comportamiento malicioso. El programa funciona escaneando archivos de registro y reaccionando a acciones ofensivas como los repetidos intentos fallidos de inicio de sesión.

```bash
apt-get install fail2ban
```

Ahora hacemos una copia local del archivo de configuración:

```bash
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

Y seguimos configurándolo:

```bash
nano /etc/fail2ban/jail.local
```

Comenzamos con la sección [DEFAULT], editando estas líneas:

```bash
ignoreip = 127.0.0.1/8 192.168.1.0/24
bantime  = 3600
maxretry = 3
```
Esto admitirá la dirección local (127.0.0.1/8) y la red local (192.168.1.0/24), y rechazará una ip maliciosa después de 3 intentos de login incorrectos, durante 1 hora (3600 segundos).



Ahora la sección [JAILS], debajo de SSH verás:

```bash
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 6
```

Esta es la configuración específica para el servicio SSH, no necesitamos cambiarlo, pero si cambias el puerto estándar de ssh (22) a otro, deberás configurarlo:

```bash
port     = 33000 # for example
```

Perfecto, lo tenemos; salvamos el archivo, lo cerramos y reiniciamos fail2ban:

```bash
/etc/init.d/fail2ban restart
```

Ok, la configuración del usuario y SSH login protegido y testado, si todo está funcionando correctamente, la próxima historia, "Net".


## Net

En esta etapa, básicamente, queremos conectar nuestro servidor Raspbian a nuestra red local vía Ethernet y acceder a él por SSH para continuar la instalación y configuración, porque probablemente no vamos a hacerlo siempre desde el mismo lugar, a veces trabajamos en nuestra casa, o en casa de amigos, o trabajamos en equipo en algún lugar, o lo que sea.

El punto es, no queremos comprobar cada vez el número IP de nuestro RPi, no queremos tener DHCP (por defecto) que le asigna una nueva IP cada vez que conectamos nuestro RPi a un nuevo router, por lo que desactivamos el DHCP, y asignamos una IP estática. Eso significa que nuestro servidor Raspbian, localmente, siempre tendrá el IP que elegimos. Esto es realmente trivial, así que hagámoslo.


1 - Abrir el archivo /etc/network/interfaces

```bash
nano /etc/network/interfaces
```

2 - Verás una línea como esta:

```bash
iface eth0 inet dhcp
```

Esta es la configuración predeterminada para eth0, el dispositivo Ethernet estándar RPi, con DHCP habilitado. [DHCP](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol) es un protocolo comúnmente utilizado por la  mayoría de routers para asignar dinámicamente un IP libre al dispositivo conectado. Esta es la elección fácil, pero no lo que queremos aquí (no por la parte "fácil"), sólo queremos que nuestro RPi tenga siempre el mismo número IP (estático).

3 - Así que comentamos la línea de configuración predeterminada de DHCP y añadimos una IP estática:

```bash
#iface eth0 inet dhcp
iface eth0 inet static
  address your.static.ip.number # Ex. 192.168.1.59
  gateway your.router.ip.number # Ex. 192.168.1.1
  netmask 255.255.255.0
```

La dirección y máscara de red van de acuerdo con la configuración de tu router, pero los datos del ejemplo anterior son muy comunes.

4 - Guardar el archivo y cerrarlo.

¡Lo tenemos! Prueba a reiniciar tu RPi y comprueba la dirección IP asignada a eth0:

```bash
ifconfig eth0 | grep inet
```

Si todo es correcto, el dato de salida debería mostrar la IP y máscara de red que has configurado en el archivo /etc/network/interfaces

Ok, así que coge tu RPi, un cable ethernet, y los pones en tu bolsa, ahora podremos trabajar en nuestro servidor desde cualquier lugar con un router; conectamos el RPi, lo iniciamos, y desde otro equipo conectado al mismo router, accedemos por ssh a nuestro servidor, ¡genial!


Echemos un vistazo ahora a una herramienta muy útil para cuando estamos trabajando con cosas de red, [netstat](https://www.lifewire.com/netstat-linux-command-4095695)

```bash
netstat -apt
```

Esto nos da, como datos de salida, todas las conexiones tcp activas (escuchadas y establecidas), mi salida:

```bash
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 RPi.static.ip:22        *:*                     LISTEN      294/sshd        
tcp        0      0 RPi.static.ip:22        client.ip.number:22     ESTABLISHED 388/sshd: username
```

Todo parece ok, tenemos nuestro daemon SSH escuchando en el puerto 22 y nuestra conexión ssh activa establecida.
El puerto 22 es el puerto estándar para SSH, pero ¿cuáles son los números de puerto estándar para otros servicios? Para responder a esto, lo mejor que podemos hacer es echar un vistazo a la lista de puertos estándar comunes en un servidor.

Super fácil, solo mirar los datos del archivo /etc/services

```bash
cat /etc/services
```
Servicios, puertos y netstat, vamos a utilizar mucho esta herramienta, así que pruébala y siéntete confortable con ella.

Ok, vamos a hacer una pausa aquí, es el momento de update/dist-upgrade, vamos a repetir este paso varias veces a lo largo de toda la configuración del servidor:

```bash
apt-get update && apt-get dist-upgrade
```

Para obtener todas las actualizaciones de nuestro sistema raspbian actual, y:

```bash
apt-get clean
```

Para limpiar el espacio del disco eliminando archivos de instalación de actualizaciones temporales.

En una sola línea:

```bash
apt-get update && apt-get dist-upgrade -y && apt-get clean
```

Hasta ahora muy bien, ya tenemos una puerta de acceso segura en nuestro servidor Raspbian, ahora podemos comenzar a instalar y configurar todos nuestros servicios, más o menos dependiendo de lo que necesitamos de nuestro servidor, pero este es el próximo capítulo así que, te veo en un rato.


## DNS

Antes de continuar con las instalaciones y configuraciones, necesitamos decirle al sistema dónde pedir una IP <--> asociada al nombre de un dominio, y para eso necesitamos usar lo que se llama Domain Name System Server (servidor DNS), básicamente necesitamos pasar al sistema la ip de uno o varios servidores DNS para que sea capaz de obtener la IP de un dominio o viceversa.

Usaremos aquí los servidores estándar [OpenDNS](https://www.opendns.com), pero puedes utilizar el que más te guste.

Para ello editamos el archivo /etc/resolv.conf:

```bash
nano /etc/resolv.conf
```

Y añade los datos IP de tus servidores DNS, en el caso de usar OpenDNS:

```bash
nameserver 208.67.222.222
nameserver 208.67.220.220
```

Guardar el archivo, cerrarlo y reiniciar. ¡HECHO!


## Services

Desde [wikipedia](https://en.wikipedia.org/wiki/Server_(computing)): "Los servidores pueden proporcionar varias funcionalidades, a menudo llamadas 'servicios', como compartir datos o recursos entre varios clientes o procesar cálculos para un cliente".

![CERN First WWW Server](https://upload.wikimedia.org/wikipedia/commons/2/2c/First-server-cern-computer-center.jpg)
**The first HTTP web server of the history, year 1990 (from CERN, where they actually invented the web!)**

¿Por qué estamos construyendo un servidor? Esto es lo que necesitas preguntarte ahora mismo. Porque dependiendo de cuál sea la respuesta, el contenido de este capítulo cambiará mucho, pero de todos modos, vamos mantenernos frescos y cubrir al menos todos los servicios básicos, y tal vez algo más. Hagámoslo.
No hay un orden mejor o específica para instalar los servicios, así que utilizaré el mío, tu puedes cambiarlo, y por supuesto las contribuciones son bienvenidas y muy apreciadas.


### SFTP

Entonces, empezaremos con la implementación de un servicio SFTP con un Chroot'ed Isolated File Directory, WHAAAAAAAAT?

Bueno, sí, no es como hacer doble clic en el icono :P, porque aquí estamos tratando de hacer cosas distintas, y el título tutorial dice "Secure Server Config ...", pero no te preocupes, vamos a desgranarlo paso a paso.


**Paso 1**, ¿qué es SFTP? Desde [digitalocean](https://www.digitalocean.com/community/tutorials/how-to-use-sftp-to-securely-transfer-files-with-a-remote-server) : "Significa Protocolo de Transferencia de Archivos SSH o Protocolo de Transferencia Segura de Archivos, es un protocolo separado empaquetado con SSH que funciona de manera similar a través de una conexión segura. La ventaja es la capacidad de aprovechar una conexión segura para transferir archivos y recorrer el sistema de archivos en sistema local y remoto"

**Paso 2**, ¿Qué diablos significa chroot'ed? Desde [wikipedia](https://en.wikipedia.org/wiki/Chroot) : "Un chroot en los sistemas operativos Unix es una operación que cambia el directorio raíz aparente para el proceso en ejecución actual y sus hijos. Un programa que se ejecuta en un entorno modificado no puede nombrar (y por lo tanto normalmente no puede acceder) archivos fuera del árbol de directorios designado El término "chroot" puede referirse a la llamada de sistema chroot (2) o al programa ejecutable chroot(8). El entorno modificado se denomina cárcel chroot."

**Paso 3**, En resumen, vamos a implementar un servicio de protocolo de transferencia de ficheros seguro y difícil de hackear para nuestro Rasbian Server, ¡síiiii! Con este servicio podremos conectarnos de forma segura con nuestro servidor y cargar archivos, incluso podemos dejar que alguien más acceda a nuestro servidor para cargar/descargar archivos, pero en un entorno de jaula chroot, como una burbuja sin salidas, un entorno chroot es sólo el universo observable, por lo que el resto del sistema, donde no queremos que nadie mire, (ver [Directory traversal attack](https://en.wikipedia.org/wiki/Directory_traversal_attack)), no existirá para ellos.


**Paso 4**, instalar OpenSSH server software

```bash
apt-get install openssh-server
```

**Paso 5**, crear un grupo de usuarios para el acceso sftp y un usuario específico, esta es una buena práctica para todos los tipos de servicios, crear grupos para cada servicio con el fin de limitar el acceso, si me conecto a través de sftp, tendré acceso SÓLO a eso.


```bash
groupadd sftpgroup
```

```bash
cat /etc/group
```

Presta atención aquí a la identificación relacionada con el grupo recién creado, en mi caso es 1001:

```bash
sftpgroup:x:1001:
```

Añadir ahora un nuevo usuario que se utilizará exclusivamente para el acceso SFTP (cambia 1001 con tu ID de grupo y elije tu nombre de usuario):

```bash
sudo useradd [user name] -d /home/[user name] -g 1001 -N -o -u 1001
sudo passwd [user name]
```

* **-d** es el directorio home del usuario que debe establecerse en /home/[user name].
* **-g** es el ID asignado del grupo de usuarios, que en nuestro ejemplo necesita ser asignado al sftpgroup.
* **-N** useradd por defecto crea un grupo con el mismo nombre que el nuevo usuario, esto lo deshabilita.
* **-u** es el ID del usuario, que en nuestro caso necesita tener el mismo valor ID que sftpgroup.
* **-o** permite IDs de usuario duplicadas y no únicas.
* El comando **passwd** establece una contraseña de usuario encriptada.




Ahora comprobamos en el sistema la lista de usuarios para ver si todo ha ido bien:

```bash
cat /etc/passwd
```

En la última línea podemos ver el nuevo usuario añadido

```bash
sftpuser:x:1001:1001::/home/sftpuser:/bin/sh
```

Antes de configurar el daemon SSH, necesitamos crear un nuevo par de claves para este nuevo usuario, en mi caso sftpuser. Es lo mismo que lo hicimos antes para el usuario regular de conexión ssh (en el apartado SSH). Por lo que ahora nos servirá para refrescar un poco lo aprendido:


1 - Generar el nuevo par de claves en tu ordenador local:

```bash
ssh-keygen -t rsa -b 4096 -C "raspbian_sftp_key"
```

2 - Copiar la clave pública en el servidor:

```bash
ssh-copy-id -i myKey.pub sftpuser@RPI_ip_number
```

3 - Eso es todo. Para comprobarlo, salimos de la sesión actual de ssh y la iniciamos de nuevo con el nuevo sftpuser.

**Paso 6**, ahora necesitamos editar el archivo de configuración del daemon SSH, lo mismo que editamos para la conexión SSH hace algún tiempo, ¿recuerdas? Vamos a hacerlo:


```bash
nano/etc/ssh/sshd_config
```

Buscar la línea:

```bash
Subsystem sftp /usr/lib/openssh/sftp-server
```

Y cambiarla por:

```bash
#Subsystem sftp /usr/lib/openssh/sftp-server
Subsystem sftp internal-sftp
```


Ahora la parte más interesante, vamos al final del documento y agregamos el siguiente bloque:

```bash
Match group sftpgroup
ChrootDirectory /var/www
X11Forwarding no
AllowTcpForwarding no
ForceCommand internal-sftp
```

Esta es la parte donde confinamos el grupo de usuarios sftpgroup al directorio /var/www (no podrán escapar de allí, o al menos tendrán que sudar).
Utilizamos /var/www porque es el directorio estándar para servidores web, pero si quieres puedes elegir otro nombre para la  carpeta, como /var/sftp por ejemplo.
Este paso es realmente importante, si se nos olvida configurar el ChrootDirectory para este grupo de usuarios específicos, algún usuario conectado podría obtener acceso a / (el nivel root del servidor) y eso es justo lo que no queremos!!!

Y lo último, muy importante, añade el nuevo usuario, sftpuser, en la línea AllowUsers:

```bash
AllowUsers  user sftpuser
```

Guardamos el archivo y

**Paso 7**, creamos la carpeta /var/www, si no lo has hecho ya:

```bash
mkdir /var/www
```

**Paso 8**, creamos tres carpetas de prueba: una de sólo lectura, otra de lectura/escritura y la última que no permite el acceso:

```bash
cd /var/www
mkdir test_readonly
mkdir test_readwrite
mkdir test_noaccess
```

En este momento las tres carpetas tienen los mismos permisos, vamos a explicarlo un poco:

```bash
ls -la
```

Me devuelve (estamos en /var/www):

```bash
drwxr-xr-x  5 root root 4096 Mar 26 05:41 .
drwxr-xr-x 12 root root 4096 Mar 26 05:37 ..
drwxr-xr-x  2 root root 4096 Mar 26 05:41 test_noaccess
drwxr-xr-x  2 root root 4096 Mar 26 05:40 test_readonly
drwxr-xr-x  2 root root 4096 Mar 26 05:41 test_readwrite
```

Aquí vemos una lista con el contenido de la carpeta, sólo tiene las tres carpetas que acabamos de crear, y a la izquierda tenemos el tipo de permiso:

drwxr-xr-x

Vamos a verlo por partes, pero por ahora nos centraremos en estos los últimos tres bloques:

rwx   r-x   r-x

El primero de la izquierda representa los permisos de root, el segundo en el centro representa los permisos de grupo y el tercero de la derecha representa los permisos para todos los demás, y podemos leerlo de esta manera:

r w x  -->  2^2 2^1 2^0  -->  4  2  1

Y en bits podemos leerlo:

r w x --> 1 1 1

r - x --> 1 0 1

Y así sucesivamente

Así que tenemos algunas posibilidades, pero no demasiadas:

* 0 - No permiso
* 1 - Permiso para ejecutar
* 2 - Permiso de escritura
* 3 - Permiso para ejecutar+escribir
* 4 - Permiso de lectura
* 5 - Permiso para ejecutar y leer
* 6 - Permiso para leer y escribir
* 7 - Permiso para ejecutar, leer y escribir

Más información sobre los permisos en Linux [here](http://en.wikipedia.org/wiki/File_system_permissions#Symbolic_notation)

Sabiendo esto, volvemos a nuestra lista:

```bash
drwxr-xr-x  5 root root 4096 Mar 26 05:41 .
drwxr-xr-x 12 root root 4096 Mar 26 05:37 ..
drwxr-xr-x  2 root root 4096 Mar 26 05:41 test_noaccess
drwxr-xr-x  2 root root 4096 Mar 26 05:40 test_readonly
drwxr-xr-x  2 root root 4096 Mar 26 05:41 test_readwrite
```

Ahora tenemos todas las carpetas con permisos del tipo 755 (rwx r-x r-x), y esto está bien para la carpeta test_readonly, pero tenemos que cambiar los permisos de las otras dos:

```bash
chown root:sftpgroup test_readwrite
chmod 775 test_readwrite
```

Con esto asignamos, en la carpeta test_readwrite, a root como propietario y a sftpgroup como grupo de la carpeta, y con los permisos en 775, concedemos permiso completo al propietario (7), permisos completos al grupo asignado (7) y permiso para ejecutar + lectura (5) para todos los demás.



Así que para la carpeta noaccess establecemos permisos del tipo 711, ejecutar sólo para el grupo y todos los demás:

```bash
chmod 711 test_noaccess
```

Y nuestra lista de nuevo:

```bash
drwxr-xr-x  5 root root      4096 Mar 26 05:41 .
drwxr-xr-x 12 root root      4096 Mar 26 05:37 ..
drwx--x--x  2 root root      4096 Mar 26 05:41 test_noaccess
drwxr-xr-x  2 root root      4096 Mar 26 05:40 test_readonly
drwxrwxr-x  2 root sftpgroup 4096 Mar 26 05:41 test_readwrite
```

**Paso 9**, ¡Pruébalo! Hemos terminado. Ahora reiniciar el servidor SSH:

```bash
/etc/init.d/ssh restart
```

**Paso 10**, conectarse a nuestro servidor por SFTP desde un cliente, yo estoy usando [FileZilla](https://filezilla-project.org/):

Crear una nueva conexión, con la IP server de tu servidor Raspbian, el puerto 22, el Protocolo SFTP, y el archivo clave como tipo de acceso, pon el nombre del usuario, "sftpuser" en mi caso, y establecer la ruta a la clave privada del par de claves que creamos recientemente en el paso 5.  

Si todo está correcto, ahora podemos navegar por nuestra carpeta del servidor /var/www desde un cliente FileZilla, ¡genial!

Siguiente historia, instalar Apache web server


### Apache

Un servidor web, ¡suena a problemas! Y, no es falso, pero ahí vamos. Empezaremos dando un paso atrás para hablar de algo indispensable, el cortafuegos y, prepárate, volveremos a este tema muchas veces, cuando instalemos todas las cosas de nuestro servidor.
Un servidor sin un buen cortafuegos configurado es como una caja fuerte sin puerta, su contenido probablemente no durará hasta el final del día. Así que vamos a aprender algo acerca de los firewalls de linux!

El cortafuegos estándar de Debian se llama iptables (para IPv4 e ip6tables para IPv6), así que usaremos eso, primer paso:

```bash
apt-get install iptables iptables-persistent
```

El paquete iptables-persistent se utiliza para hacer que nuestras reglas de cortafuegos sean persistentes durante los reinicios.

Ok, ahora imprime las reglas actuales de iptable, ninguna ahora mismo:

```bash
iptables -L
```

Mi salida:

```bash
Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
```

Y un comando útil para limpiar todas las reglas (como resetear el firewall):

```bash
iptables -F
```

Ahora, no queremos que nuestro servidor nos bloquee, y es muy fácil que jugando con el cortafuegos nos deje bloqueados, por lo que antes que nada, agregamos una regla que nos asegure mantener intactas todas las conexiones actuales (básicamente nuestra actual conexión ssh):

```bash
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

En inglés, le decimos a iptables a **-A** anexar la regla, **INPUT** a la cadena de entrada, **-m conntrack --ctstate ESTABLISHED,RELATED** relacionar esta regla con las conexiones actuales SÓLO, **-j ACCEPT** JUMP para aceptar y la conexión todavía está en su lugar.


Si listamos nuestras reglas de nuevo:

```bash
iptables -L
```

Veremos algo nuevo, la "puerta" abierta para las conexiones entrantes actuales (nuestra conexión SSH), ¡increíble!

Ahora, empezamos a diseñar nuestro cortafuegos por lo básico de lo que ya tenemos (SSH, SFTP y pronto servidor web Apache), a lo largo del camino volveremos y añadiremos nuevas reglas para todas las otras cosas que necesitaremos en nuestro servidor. Tal vez sea buena idea preparar una nueva taza de café, o lo que te guste beber.

Comencemos por bloquear las conexiones inseguras, actualmente estamos usando el puerto 22 para SSH y SFTP, y queremos tener el puerto 80 (http) y el puerto 443 (https) disponibles:

```bash
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

```bash
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

```bash
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

Ahora se bloquea todo el tráfico restante:

```bash
iptables -P INPUT DROP
```

Permitir acceso loopback (**-I INPUT 1** colocar esta regla primero en la lista, IMPORTANTE):

```bash
iptables -I INPUT 1 -i lo -j ACCEPT
```

Y no olvides permitir conexiones salientes (para apt-get, navegación web, enviar correo, etc.)

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

Listar ahora las regla en modo detallado:

```bash
iptables -L -v
```

Mi salida:

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

Ahora tenemos nuestro cortafuegos básico! Vamos a guardarlo (no cambies la ruta de guardar archivos /etc/iptables/rules.vX):

```bash
iptables-save > /etc/iptables/rules.v4
```

Reinicia tu servidor Raspbian y verifica si todo está bien, y si las reglas se cargan automáticamente.

Estamos listos ahora para comenzar con la instalación/configuración de Apache, vamos a hacerlo:

```bash
apt-get install apache2
```

Ahora, desde un navegador cliente, vamos a comprobar si está funcionando, copia en la url la ip de tu servidor Raspberry y pulsa enter
![Apache web server](http://www.d3cod3.org/RSS/apache_screenshot.jpg)

Eso es, Apache instalado y funcionando! Ahora la configuración:

* 1 - Ocultar la versión de Apache:

```bash
nano /etc/apache2/conf-enabled/security.conf
```

Y añadir/editar estas líneas:

```bash
ServerSignature Off
ServerTokens Prod
```

Guardar y reiniciar Apache2:

```bash
/etc/init.d/apache2 restart
```

* 2 - Desactivar la exploración de directorios, deshabilitar enlaces simbólicos, limitar el tamaño de solicitud (a 600 Kb) y desactivar Server Side Includes, así como ejecución CGI

```bash
nano /etc/apache2/apache2.conf
```

Después, editar las siguientes líneas:

```bash
<Directory /var/www/>
        LimitRequestBody 614400
        Options -FollowSymLinks -Includes -ExecCGI
        AllowOverride None
        Require all granted
</Directory>
```

Guardar y reiniciar de nuevo.

* 3 - Deshabilitar módulos innecesarios y reiniciar de nuevo:

```bash
a2dismod autoindex
a2dismod status
/etc/init.d/apache2 restart
```

* 4 - Instalar módulos adicionales:

```bash
apt-get install libapache2-mod-security2
```

ModSecurity necesita estar habilitado:

```bash
mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
nano /etc/modsecurity/modsecurity.conf
```

Y edita esta línea:

```bash
#SecRuleEngine DetectionOnly
SecRuleEngine On
```

Reinicia el servicio Apache e instala el siguiente módulo:

```bash
apt-get install libapache2-mod-evasive
```

Luego agrega esto al final de /etc/apache2/apache2.conf:

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

Reinicie apache de nuevo, y lo hemos conseguimos! Ahora es el momento para el siguiente componente, el servidor MySQL!

### MySQL Server

Primer paso, instalarlo, fácil (siempre usa contraseñas seguras):

```bash
apt-get install mysql-server
```

Y, para asegurar la instalación:

```bash
mysql_secure_installation
```

Vamos a probarlo:

```bash
mysql -u root -p
```

Y entrarás en la consola de mysql, perfecto! ¡Ahora instalar PHP!

### PHP

Ahora, aquí tenemos un pequeño problema, el último Raspbian está basado en Debian Jessie, que todavía viene con PHP 5.6 por defecto (desde la rama estable), pero no queremos una release de PHP tan antigua y casi sin soporte (y más insegura), queremos instalar PHP 7, la última versión. Para hacerlo, tendremos que ajustar un poco nuestro sistema apt, vamos a llegar hasta él:

```bash
nano /etc/apt/sources.list
```

Y añadir al final:

```bash
# TWEAK - Stretch (testing) branch for PHP7 install on Jessie
deb http://mirrordirector.raspbian.org/raspbian/ stretch main contrib non-free rpi
```

Ahora, no queremos que cada paquete se actualice o se instale desde la rama de prueba (testing). Para ello podemos establecer algunas preferencias para que todos los paquetes se seleccionen de Jessie de forma predeterminada. Abre el siguiente archivo **/etc/apt/preferences**, y añade los siguiente:

```bash
Package: *
Pin: release n=jessie
Pin-Priority: 600
```

Guardar el archivo y actualizar:

```bash
apt-get update
```

Lo tenemos, cada vez que queramos instalar algo desde la rama de pruebas, lo haremos así (esto actualizará el paquete apache2, cuando te pregunte, mantén los archivos de configuración actuales):

```bash
apt-get install -t stretch php7.0-cli php7.0-dev php-pear libapache2-mod-php7.0 php7.0-mysql php7.0-mcrypt php7.0-sqlite3 php7.0-bcmath php7.0-bz2 php7.0-curl php7.0-gd php7.0-imap php7.0-mbstring php7.0-odbc php7.0-pgsql php7.0-soap php7.0-xml php7.0-xmlrpc php7.0-zip
```

Y, para solucionar algunos problemas debido a este cambio de repositorio:

```bash
apt-get install -t stretch mailutils maildir-utils sendmail-bin
apt-get install sensible-mda
```

En este punto tendremos que esperar un poco más, así que aprovecharé para aclarar algo. Al utilizar la rama de prueba (desde Debian stretch), estamos mezclando paquetes "todavía no marcados como estables" en nuestro sistema, esto no es una buena política para un servidor orientado a la seguridad, pero una versión más antigua de php es sin duda un peor escenario, por lo que ponte las pilas, acabas de pasar al siguiente nivel, un poco más desafiante. Se siente miedo, pero no mientas ¡te está gustando!

Ahora, el último módulo específico de [GnuPG](https://gnupg.org/) para encriptación:

```bash
apt-get install -t stretch gnupg libgpg-error-dev libassuan-dev
```

Ves a una carpeta temporal y descargua la biblioteca gpgme:

```bash
wget https://www.gnupg.org/ftp/gcrypt/gpgme/gpgme-1.8.0.tar.bz2
```

Extraer, configurar, e instalar make && make:

```bash
tar xvfj gpgme-1.8.0.tar.bz2 && cd gpgme-1.8.0 && ./configure
```

Después:

```bash
make && make install
```

Y

```bash
pecl install gnupg
```

Lo último, abrir /etc/php/7.0/apache2/conf.d/20-gnupg.ini

```bash
nano /etc/php/7.0/apache2/conf.d/20-gnupg.ini
```

y añadir la siguiente línea:

```bash
extension=gnupg.so
```

Guardar y cerrar el archivo, y para solucionar un pequeño problema de carga de la biblioteca, abre este nuevo archivo:

```bash
nano /etc/ld.so.conf.d/userlib.conf
```

Después añade esta línea

```bash
/usr/local/lib
```

Guardar/cerrar el archivo y vuelve a ejecutar ldconfig para reconstruir la caché:

```bash
ldconfig
```

Finalmente reinicia Apache y crea un nuevo archivo para imprimir php info:

```bash
nano /var/www/html/info.php
```

A continuación, agrega el siguiente código php típico:

```bash
<?php phpinfo(); ?>
```

Ahora abre desde tu navegador la url siguiente: http://your_raspbian_server_ip/info.php, si todo salió bien verás la página de información común de php.


![PHP Install](http://www.d3cod3.org/RSS/php_install.jpg)

Hemos terminado con la instalación de PHP, ahora eliminamos el archivo de información por razones de seguridad:

```bash
rm -i /var/www/html/info.php
```

¡Esto está comenzando a parecer agradable!

Ok, vamos a hacer una pequeña pausa, y echar un vistazo mejor a lo que tenemos en este momento:

```bash
service --status-all
```

Este comando nos dará la lista completa de servicios disponibles en nuestro servidor, donde [ + ] significa servicio iniciado, [ - ] servicio parado y [ ? ] estado desconocido.

Pero echemos un vistazo más profundo con otro programa:


```bash
apt-get install chkconfig
```

y

```bash
chkconfig --list
```

Esto nos mostrará la disponibilidad de nuestros servicios en todos los runlevels (niveles de ejecución) diferentes. No hay espacio aquí para desarrollar una clase sobre runlevel, así que [here](https://en.wikipedia.org/wiki/Runlevel) más información.

Y otra herramienta muy potente para descubrir los servicios es el sistema init systemd:

```bash
systemctl list-units -t service
```

Y como hicimos antes con netstat, vamos a comprobar todas las conexiones tcp activas:

```bash
netstat -atp
```

Mi salida:

```bash
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 localhost:smtp          *:*                     LISTEN      1151/exim4
tcp        0      0 192.168.1.104:22        *:*                     LISTEN      310/sshd
tcp        0      0 localhost:mysql         *:*                     LISTEN      781/mysqld
tcp        0     92 raspbian.ip.number:22   client.ip.number:port   ESTABLISHED 1188/sshd: username
tcp6       0      0 localhost:smtp          [::]:*                  LISTEN      1151/exim4
tcp6       0      0 [::]:http               [::]:*                  LISTEN      736/apache2
```

Como puedes ver, tenemos nuestros servicios recién instalados de Apache2 y MySQL escuchando, nuestra conexión SSH activa establecida, y una nueva, el servicio exim4 escuchando también, pero no instalamos este exim4, ¿qué es esto? Bueno, cuando instalamos php7, una de sus dependencias es el servicio exim4 para enviar información del sistema a usuarios internos, por lo que el sistema lo instaló automáticamente.

Próxima historia, un bono especial: Ruby on Rails!


### Ruby on Rails with rbenv (EXTRA BONUS - NIVEL INTERMEDIO!!!)

Ruby on Rails es un framework de desarrollo web rápido que permite a diseñadores web y desarrolladores implementar aplicaciones web dinámicas con todas las funciones.
Personalmente, creo que RoR es realmente mejor opción que PHP, y no soy el único, pero de todos modos, busca en Internet y aprende cosas sobre él, tu eliges tenerlo, o no, en tu servidor personal.


¡Pongámonos a trabajar! Comenzamos como siempre con las dependencias:

```bash
apt-get install autoconf bison build-essential curl libssl-dev libyaml-dev libreadline6-dev zlib1g-dev libncurses5-dev libffi-dev libgdbm3 libgdbm-dev
```

y

```bash
apt-get install git-core
```

Bien, ahora instala, desde github, [rbenv](https://github.com/rbenv/rbenv):

```bash
git clone https://github.com/rbenv/rbenv.git ~/.rbenv
```

Añade su PATH para usar la utilidad de línea de comandos:

```bash
echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(rbenv init -)"' >> ~/.bashrc

source ~/.bashrc
```

Tiempo para testarlo:

```bash
type rbenv
```

Y deberías ver esto, si todo está bien:

```bash
rbenv is a function
rbenv ()
{
    local command;
    command="$1";
    if [ "$#" -gt 0 ]; then
        shift;
    fi;
    case "$command" in
        rehash | shell)
            eval "$(rbenv "sh-$command" "$@")"
        ;;
        *)
            command rbenv "$command" "$@"
        ;;
    esac
}
```

Y recuerda, de vez en cuando, actualizar rbenv, ya que se instala desde Git, y tendremos que hacerlo manualmente:

```bash
cd ~/.rbenv
git pull
```

¡Perfecto! Ahora instale un plugin rbenv para hacer la vida más fácil, [ruby-build](https://github.com/rbenv/ruby-build):

```bash
git clone https://github.com/rbenv/ruby-build.git ~/.rbenv/plugins/ruby-build
```

En este punto, tenemos todas las herramientas para comenzar a instalar ruby y configurarlo correctamente, así que vamos a instalar Ruby!

Pero, aquí viene nuestro primer dilema, ¿qué versión de Ruby? Bueno, rbenv nos ayuda con eso, como lo gestiona y organiza, detrás de la cortina, una o múltiple versiones instaladas de Ruby, cool!

Podemos entonces enumerar todas las versiones disponibles en este momento:

```bash
rbenv install -l
```

Y elegir una, yo elegí 2.3.3 esta vez:

```bash
rbenv install 2.3.3
```

TE ADVIERTO, este paso puede tardar mucho, tal vez tanto como en ir a almorzar o lo que prefieras, pero un café no será suficiente!
Nos vemos en un momento :P

OK, estamos de vuelta y Ruby está instalado, mi salida:

```bash
Installed ruby-2.3.3 to /home/your_username/.rbenv/versions/2.3.3
```

Por último, establecer esta versión como predeterminada:

```bash
rbenv global 2.3.3
```

Y testarlo, obviamente:

```bash
ruby -v
```

Mi salida:

```bash
ruby 2.3.3p222 (2016-11-21 revision 56859)
```

Genial, ahora necesitamos configurar Gems (paquetes que amplían la funcionalidad de Ruby), desactivamos la documentación local para tener más velocidad, e instalamos un administrador de dependencias llamado **bundler**:

```bash
echo "gem: --no-document" > ~/.gemrc
gem install bundler
```

Mi salida:

```bash
Fetching: bundler-1.15.1.gem (100%)
Successfully installed bundler-1.15.1
1 gem installed
```

Vamos a comprobar si la ruta de Gems es correcta:

```bash
gem env home
```

Mi salida:

```bash
/home/your_username/.rbenv/versions/2.3.3/lib/ruby/gems/2.3.0
```

Bien, Gems está correctamente configurado, ahora instalamos Rails:

```bash
gem install rails
```

Esto, puede tardar un poco ...
Cuando termine, como siempre, verificamos la versión instalada:

```bash
rails -v
```

Y mi salida es:

```bash
Rails 5.1.2
```

SUPER! Ahora necesitamos instalar JavaScript Runtime, porque algunas características de Rails dependen de él:

```bash
cd /tmp
\curl -sSL https://deb.nodesource.com/setup_6.x -o nodejs.sh
```

Y echamos un vistazo al script del archivo que acabamos de descargar (por si acaso):

```bash
less nodejs.sh
```

Si estamos satisfechos y todo es correcto, salimos tecleando **q**

Ok, vamos a instalar el repositorio NodeSource Node.js v6.x:

```bash
cat /tmp/nodejs.sh | sudo -E bash -
```

Donde el indicador -E utilizado aquí conservará las variables de entorno existentes del usuario.

Casi hecho, ahora podemos simplemente instalar nodejs a través de apt:

```bash
apt-get install nodejs
```

¡Y ya está! ¡Podemos comenzar a probar nuestra instalación de Ruby on Rails!
Existen diferentes opciones para implementar una aplicación Ruby on Rails, vamos a intentar utilizar nuestro servidor web Apache ya instalado.
Para ello, necesitamos el Módulo Passenger Apache.
El repositorio de Debian viene con una versión anterior del libapache2-mod-passenger, por lo que instalamos la versión correcta a través de gem:

```bash
# First install some dependencies
apt-get install libcurl4-openssl-dev apache2-threaded-dev

# Install Passeneger module
gem install passenger

# Install Passenger + Apache module
passenger-install-apache2-module
```

Ahora sigue las instrucciones y el módulo se compilará (maldito tiempo de la taza de café).

Necesitamos ahora configurar correctamente apache para que Passenger funcione correctamente:

```bash
nano /etc/apache2/mods-available/passenger.load
```

Y copia la línea sugerida en las instrucciones previas de la instalación de Passenger:

```bash
LoadModule passenger_module /home/user/.rbenv/versions/2.3.3/lib/ruby/gems/2.3.0/gems/passenger-5.1.5/buildout/apache2/mod_passenger.so
```

Después:

```bash
nano /etc/apache2/mods-available/passenger.conf
```

Y copia:

```bash
<IfModule mod_passenger.c>
        PassengerRoot /home/your_user_name/.rbenv/versions/2.3.3/lib/ruby/gems/2.3.0/gems/passenger-5.1.5
        PassengerDefaultRuby /home/your_user_name/.rbenv/versions/2.3.3/bin/ruby
</IfModule>
```

Y el último paso, habilitar el módulo y reiniciar apache:

```bash
a2enmod passenger
service apache2 restart
```

Bien, ahora vamos a entender cómo implementar nuestras aplicaciones Rails, pero para ello, primero necesitamos una!
Como siempre, vamos a utilizar una aplicación de prueba, y con la ayuda de las herramientas previamente instaladas, será súper fácil!


Comenzaremos creando un nuevo directorio para almacenar aplicaciones de rails:

```bash
cd /home/your_username/ &&  mkdir your_rails_dev_folder_name
```

Y creamos una aplicación de prueba:

```bash
rails new testapp --skip-bundle
```

Perfecto, entra al directorio y modifica Gemfile para instalar un entorno de ejecución JavaScript:

```bash
cd testapp && nano Gemfile
```

Ahora, busca esta línea:

```bash
# gem 'therubyracer',  platforms: :ruby
```

Borra el signo de comentario, guarda el archivo y ciérralo.

Muy bien, ahora inicia la instalación automática (gracias (bundler)[https://bundler.io/]):

```bash
bundle install
```

WOW!, estamos casi terminando, Apache está funcionando bien con el módulo Passenger configurado, Ruby on Rails está bien afinado con rbenv, ahora vamos a comprobar si todo está sonando, y, finalmente, vamos a crear un archivo de host virtual para probar nuestra aplicación Rails.

La prueba:

```bash
passenger-memory-stats
```

Y mi salida:

```bash
--------- Apache processes ---------
PID  PPID  VMSize    Resident  Name
------------------------------------
855  1     12.8 MB   6.3 MB    /usr/sbin/apache2 -k start
899  855   232.1 MB  5.9 MB    /usr/sbin/apache2 -k start
900  855   230.0 MB  4.2 MB    /usr/sbin/apache2 -k start


-------- Nginx processes ---------



---- Passenger processes -----
PID   VMSize   Resident  Name
------------------------------
861   30.7 MB  8.1 MB    Passenger watchdog
866   93.9 MB  11.4 MB   Passenger core
877   39.1 MB  8.9 MB    Passenger ust-router
```

Puedes ver los procesos de Apache y los de Passenger en funcionamiento, GRANDE!

Finalmente, creamos un nuevo archivo de host virtual para nuestra aplicación de Rails **testapp**:

```bash
cp /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-available/testapp.conf
nano /etc/apache2/sites-available/testapp.conf
```

El archivo debe tener este aspecto:

```bash
<VirtualHost *:80>

        ServerAdmin webmaster@localhost
        DocumentRoot /home/your_username/rails_folder/testapp/public
        RailsEnv development

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        <Directory "/home/your_username/rails_folder/testapp/public">
                Allow from all
                Options -FollowSymLinks -MultiViews
                Require all granted
        </Directory>

</VirtualHost>
```

Después, deshabilita el host virtual predeterminado de Apache, y habilita el nuevo de **testapp** rails, y reinicia apache:

```bash
a2dissite 000-default
a2ensite testapp
service apache2 restart
```

¡Y ESO ES TODO! Abre en tu navegador la IP del servidor Raspbian y echa un vistazo:

![Raspbian RoR](http://www.d3cod3.org/RSS/raspbian_rails.jpg)


Con esto nuestro servidor está empezando a tener todas las piezas en su lugar.
Siguiente historia? Ocultar el servicio SSH!


## Hide

Esta es la última capa de seguridad que vamos a agregar a los servicios de SSH y SFTP, es una especie de técnica avanzada de ofuscación, y no todos estarán de acuerdo en que sea realmente útil, pero bueno, en mi opinión, añade algunas dificultades a un posible atacante cuando intente acceder a nuestro servidor, por eso vamos a instalar un sistema de golpeo de puertos, en inglés, port knocker.
Y, ¿qué es un port knocker? Es un tipo especial de servicio disfrazado que escucha una secuencia específica de "golpes" en una lista predefinida de puertos, cuando los puertos de esta lista son "golpeados" correctamente, este servicio abre temporalmente el puerto especificado (la puerta de acceso al servidor por SSH es el puerto 22) para dar acceso, y cerrarlo de nuevo después de iniciar sesión.
Es lo mismo que llamar a la puerta de casa con un código de golpes predefinido, si desde dentro reconocen el código acordado alguien abre la puerta, y vuelva a cerrarla una vez que se esté dentro.
Por lo tanto, en términos de visibilidad (exploración de puertos por ejemplo), nuestro servidor será invisible, porque ante la pregunta: ¿está escuchando el puerto SSH?, la respuesta será NO.

Pero ¡ATENCIÓN! Hay un debate abierto sobre la eficacia real de las técnicas de golpeo de puertos (port Knocking) que pone en duda si realmente aportan más seguridad, así que busca en Internet y lee sobre él, después, elige si deseas instalarlo en tu servidor, o no.

### Port Knock

Vamos a instalar el port knocker estándar de Debian:

```bash
apt-get install knockd
```

Después, editamos su archivo de configuración principal, /etc/knockd.conf, verás algo como esto:

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

Y lo cambiamos para que se vea así:

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

Veamos lo que he propuesto. Primero comentamos los bloques [openSSH] y [closeSSH], y después añadimos un nuevo bloque llamado [SSH], esto es porque queremos cerrar automáticamente el puerto 22, segundos después de que se haya abierto, no queremos tener diferentes secuencias de golpeo para la primera apertura y luego cerrar el puerto.
En nuestro nuevo bloque [SSH] hemos configurado la secuencia de pulsación de puertos con una secuencia aleatoria (he usado 5004,1233,8732,1112,6, elige la tuya), el tiempo para recibir los golpes (seq_timeout), el tiempo que el sistema espera para cerrar el puerto después de la apertura (cmd_timeout), después el comando para abrir el puerto (start_command, una regla iptables que momentáneamente nos da acceso al puerto) y finalmente el comando para cerrar (stop_command).


Ok, ahora edita otro archivo, /etc/default/knockd y haz lo siguiente:

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

Ya está, reinicia el servicio knockd y pruébalo:

```bash
/etc/init.d/knockd restart
```

Ahora, antes de terminar de configurar el cortafuegos y ocultar nuestro servicio SSH, tenemos que asegurarnos de que está funcionando, porque si no lo configuramos correctamente, o algo va mal, ¡no tendremos acceso a nuestro servidor! El firewall cerrará el puerto 22, y necesitaremos acceder directamente al servidor para solucionar el problema (no es un problema si tu servidor está en tu habitación, un poco peor si  está en otro lugar ...)
Así que, vamos a probarlo!

**Desde una máquina cliente**, crea el siguiente script:

```bash
#!/bin/bash

for x in 5004,1233,8732,1112,6;
do nmap -Pn --host_timeout 201 --max-retries 0 -p $x your.rpi.server.number;
done
```

Cambia la secuencia Knock del puerto por la que hayas establecido y pon al final de esa línea la ip de tu servidor. Guarda el archivo como knock_rpi.sh.

Si en tu ordenador local (máquina cliente) no tienes nmap instalado, instálalo, [nmap](https://nmap.org/)

El momento de la verdad, activa el archivo desde el terminal en tu ordenador:

```bash
sh knock_rpi.sh
```

Luego, en tu servidor, imprime las reglas de iptables:

```bash
iptables -L -v
```

Si todo ha salido bien, verás algo similar a esta línea al principio de la cadena INPUT:

```bash
27  1872 ACCEPT     tcp  --  any    any     your.client.ip.number        anywhere             tcp dpt:ssh
```

Eso es todo, esta es la línea que llama (knocks) para añadir temporalmente al cortafuegos entrada a través del puerto 22.
Si imprimimos las reglas de iptables de nuevo, esta regla habrá desaparecido porque el comando knockd se habrá apagado, de modo que el servidor se oculta de nuevo.

Ok, el último paso, tenemos que eliminar del cortafuegos la regla que hemos configurado antes para escuchar en el puerto 22, ¿recuerdas?:

```bash
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

Para ello abrimos el archivo /etc/iptables/rules.v4:

```bash
nano /etc/iptables/rules.v4
```

Y quitamos esta línea:

```bash
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
```

¡Eso es todo! Reinicia el servidor y pruébalo!

```bash
shutdown -r now
```

Ahora, si intentamos conectarnos a través de SSH como siempre, el servidor no responderá, porque el puerto 22 está realmente cerrado. A partir de ahora, para acceder por SSH al servidor, tenemos que "golpear" antes, y luego pedir una conexión SSH.

Así:

```bash
sh knock_rpi.sh
```

Un poco después (como siempre):

```bash
ssh -i ~/.ssh/your_rsa_key_name -p 22 username@RPi_ip_number
```

Y eso es todo, ¡el servicio SSH está bien escondido!

Para la conexión SFTP será lo mismo, "golpear" antes de pedir la conexión!

Bueno, hemos hecho la mayor parte del trabajo, casi tenemos nuestro servidor seguro, solo necesitamos asegurar algo más, luego configurar los DNS de nuestro dominio, configurar el enrutador local y finalmente empezar a usarlo.
Pero no te apresures, vamos paso a paso, la próxima historia, "Fingerprint" las huellas digitales de tus archivos


## Security

Ahora podemos decir que el proceso no ha sido muy fácil, pero ya estamos llegando al final del viaje, y esto no significa que hayamos mirado todo lo relativo a este tema, ni que ahora seamos expertos en administración de sistemas y seguridad. Nada más lejos de la realidad, este campo es increíblemente complejo, especialmente para servidores on-line, porque necesitan mucha dedicación, continuas actualizaciones (tanto desde el lado personal como desde el de la máquina), imaginación y un montón de horas de práctica, ¡realmente mucho!

Por lo tanto, no somos expertos todavía, pero tal vez algunos de nosotros lo será algún día, quién sabe. Mientras tanto, vamos a terminar la configuración de seguridad básica para nuestro servidor personal Raspbian, los sistemas de detección de intrusiones, ahí vamos.

### RKHunter

RKHunter es un sistema de protección de [rootkit](https://es.wikipedia.org/wiki/Rootkit). Los rootkits son un problema extremadamente peligroso para los servidores on-line, si se instalan secretamente en los servidores, permiten a los intrusos entrar repetidas veces sin ser detectados. En resumen, si un servidor tiene una vulnerabilidad no resuelta, algún atacante podría usarlo para instalar un rootkit; imagina que el administrador del servidor corrige esa vulnerabilidad y cree que el servidor ahora está seguro. Pero el rootkit invisible ya estaba allí, por lo que el atacante puede volver siempre que lo desee, a través del rootkit que instaló.

Por lo tanto, es una buena idea instalar RKhunter, nos ayudará a proteger nuestro sistema de este tipo de problemas, vamos a hacerlo:

```bash
apt-get install -t stretch libwww-perl
```

Necesitamos instalarlo desde el repositorio de pruebas porque algunas dependencias de rkhunter fueron instaladas previamente por la instalación de php.

```bash
apt-get install -t stretch rkhunter
```

Esto instalará RKHunter 1.4.2, vamos a comprobarlo:

```bash
rkhunter --versioncheck
```

Ok, ahora realizamos una actualización de nuestros archivos de datos, una especie de información "base" sobre nuestro sistema de ficheros que RKHunter utilizará para los controles:

```bash
rkhunter --update
```

Ahora confirmamos a RKHunter que ésta es la línea de base desde la cual realizar las verificaciones:

```bash
rkhunter --propupd
```

Perfecto, estamos listos para hacer la ejecución inicial, probablemente producirá algunas advertencias, pero no te preocupes, es normal:

```bash
rkhunter -c --enable all --disable none
```

El proceso tarda un poco, y te pedirá que presiones la tecla Enter para ejecutar diferentes controles.

Ok, registro guardado, lo abrimos y revisamos:

```bash
nano /var/log/rkhunter.log
```

Ahora, busca las "Advertencias", yo tengo las siguientes:

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

Otra forma de hacer un chequeo completo imprimiendo solo las advertencia es:

```bash
rkhunter -c --enable all --disable none --rwo
```

Tenemos ahora un ejemplo simple de advertencias RKHunter, vamos a configurarlo un poco:

```bash
nano /etc/rkhunter.conf
```

Primero, configuramos el correo local para recibir las notificaciones cuando RKHunter hace una advertencia:

```bash
MAIL-ON-WARNING=root@localhost
MAIL_CMD=mail -s "[rkhunter] Warnings found for ${HOST_NAME}"
```

Después, solucionamos las advertencias sobre algunos paquetes binarios que han sido reemplazados por scripts:

```bash
SCRIPTWHITELIST=/sbin/chkconfig
```

Luego, permitimos que en los procesos [rotatelogs](https://httpd.apache.org/docs/2.2/programs/rotatelogs.html) Apache2 y mysqld utilicen los archivos borrados, esto no es SIEMPRE la mejor forma de hacerlo, pero en nuestro caso, tenemos una caja limpia, nadie ha tocado nuestro servidor (al menos en mi caso), y todavía no lo hemos abierto a Internet, así que no es una locura considerarlo un falso positivo, en cuyo caso decidí incluirlo en una lista blanca:

```bash
ALLOWPROCDELFILE=/usr/sbin/apache2
ALLOWPROCDELFILE=/usr/sbin/mysqld
```

Después, también incluimos en lista blanca una librería específica, compartida y precargada, de ARM RPI que nos está dando otro falso positivo:

```bash
SHARED_LIB_WHITELIST=/usr/lib/arm-linux-gnueabihf/libarmmem.so
```

Y finalmente, en mi caso, tenemos knockd instalado y escuchando la interfaz de red (nuestro golpeador de puerto), por lo que necesitamos incluirlo en la lista blanca:

```bash
ALLOWPROCLISTEN=/usr/sbin/knockd
```

Ok, chequeamos la configuración:

```bash
rkhunter -C
```

Si no hay errores, activamos un chequeo de nuevo:

```bash
rkhunter -c --enable all --disable none --rwo
```

RKHunter will tell us here that the rkhunter.conf file properties has changed, fine, so we update his db (set a new baseline):
RKHunter nos dirá que las propiedades del archivo rkhunter.conf han cambiado, bien, actualizamos su db (poner una nueva línea de base):

```bash
rkhunter --propupd
```

Eso es todo, ya podemos automatizar las comprobaciones con un [CRON job](https://en.wikipedia.org/wiki/Cron):

```bash
crontab -e
```

Con esto abrimos el archivo crontab y vamos a añadir una línea de código que le dirá al sistema que realice un chequeo rkhunter todos los días a la hora especificada:

```bash
25 05 * * * /usr/bin/rkhunter --cronjob --update --quiet
```

En esta línea le estamos diciendo a cron que rkhunter inicie un chequeo a las 05:25 am todos los días, y como está configurado, si encuentra algunas advertencias, recibiremos un correo electrónico, a la dirección especificada, con los detalles.

¡Lo tenemos! RKHunter está activo y realiza chequeos cada días. Pero recuerda, tendrás que revisar periódicamente los mensajes de advertencias, al menos una vez a la semana, para mantener todo en orden. Teniendo en cuenta que cada nuevo cambio en el sistema puede ser reconocido por rkhunter como una advertencia, por lo que siempre es necesario echar un vistazo para mantenerlo limpio de falsos positivos, de este modo en el futuro seremos capaces de reconocer los verdaderos archivos malos.

Perfecto, ahora vamos a instalar y configurar un sistema de detección de intrusión de red. La próxima historia PSAD!


### psad Network Intrusion Detection System


**psad** significa detección de ataques de exploración de puertos y es un software que supervisa los registros de cortafuegos para determinar si hay un proceso de análisis/ataque. Como rkhunter, psad puede alertar a los administradores del sistema por correo, o puede tomar medidas activas para disuadir la amenaza.

Como siempre, vamos a instalarlo:

```bash
apt-get install -t stretch psad
```

Ahora volvemos a la configuración del firewall, y agregamos las reglas necesarias a iptables para que psad pueda hacer su trabajo:

```bash
iptables -A INPUT -j LOG && iptables -A FORWARD -j LOG
```

Eso es todo, ha sido muy fácil!

Ahora vamos a ajustar la configuración de psad, abrimos el archivo psad.conf:

```bash
nano /etc/psad/psad.conf
```

Y empezamos configurando la detección de exploraciones, busca y cambia lo siguiente:

```bash
HOSTNAME    pi; # or whatever hostname you set on your raspbian server, if you don't know it, use the "hostname" command
IPT_SYSLOG_FILE         /var/log/syslog;
IGNORE_PORTS            your_port_knocking_ports;
ENABLE_PERSISTENCE          N;
MAX_SCAN_IP_PAIRS           50000;
MIN_DANGER_LEVEL            3;
EMAIL_ALERT_DANGER_LEVEL    4;
```

Ahora se actualizan las definiciones de firmas de psad y se reinicia el servicio:

```bash
psad --sig-update && /etc/init.d/psad restart
```

Antes de implementar la detección de intrusión, vamos a jugar un poco, ¡vamos a hacer una exploración de puerto!
Desde una máquina cliente ejecuta esto en el terminal:

```bash
sudo nmap -PN -sS your_rpi_server_ip
```

Esperamos a que finalice o, pasado un tiempo, lo detenemos, y luego se ejecuta en el servidor:

```bash
psad -S
```

¡AHHHHHHHHHH! No te preocupes, esto es el resultado de la exploración de puertos que has estado haciendo. Por eso está en el estado actual del servicio psad: ¡Mucha información sobre lo que pasa en nuestro servidor en red!
Muy bien, ahora es el momento de editar más configuraciones:

```bash
nano /etc/psad/auto_dl
```

Luego, añadimos:

```bash
127.0.0.1       0;
your.local.machine.ip   0; # local machine
```

Esto exime a los números IP del sistema de ser detectados como intrusión por psad, necesario para que nunca terminemos bloqueados por nuestro servidor.

Ahora vuelve al archivo de configuración principal de psad /etc/psad/psad.conf y edita lo siguiente:

```bash
ENABLE_AUTO_IDS         Y;
AUTO_IDS_DANGER_LEVEL   4;
AUTO_BLOCK_TIMEOUT   3600;
```

Esto permitirá la auto configuración de firewall, prohibiendo el acceso a un ip específico durante 60 minutos si se detecta un nivel de peligro 4 (un escáner SYN normal, por ejemplo), con esto lo conseguimos!

Es el momento para probarlo. Desde otro cliente conectado a tu red local, no desde el que tiene abierta la conexión SSH actual, ejecuta este comando:

```bash
sudo nmap -PN -sS your_rpi_server_ip
```

Mientras tanto, cierra tu conexión ssh y vuelve a conectar, luego en tu servidor visualiza las reglas reales de iptables:

```bash
iptables -S
```

Mi salida:

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

Como puedes ver, psad añadió nuevas reglas a nuestro cortafuegos, y ahora el escaneo del número IP está prohibido ahora. ¡Está funcionando!

En la siguiente historia, vamos a unir **psad** con **tripwire**, y nuestro Sistema de Detección de Intrusión será bastante bueno.

### Tripwire Intrusion Detection System

Tripwire es un sistema de detección de intrusos (HIDS) basado en host, que recoge detalles sobre nuestro sistema de archivos y configuraciones.

Primero, lo instalamos:

```bash
apt-get install tripwire
```

Responde sí a todo y pon las contraseñas que pide.

Luego, similar a rkhunter, inicializa la base de datos tripwire:

```bash
tripwire --init
```

Y realizamos un chequeo guardando el resultado en un archivo:

```bash
cd /etc/tripwire
sh -c 'tripwire --check | grep Filename > test_results'
```

Tenemos ahora una lista de inicio de reclamos de tripwire, vamos a configurarla bien para que coincida con nuestro sistema:

```bash
nano /etc/tripwire/twpol.txt
```

En la sección "Boot Scripts" comentamos la línea /etc/rc.boot, ya que no está presente en nuestro sistema raspbian:

```bash
#        /etc/rc.boot            -> $(SEC_BIN) ;
```

Y lo mismo para la sección "Root config files", comenta todas las líneas de tu archivo test_results. En mi caso:

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
        #/root/.esd_auth                -> $(SEC_CONFIG) ;
        #/root/.elm                     -> $(SEC_CONFIG) ;
        #/root/.cshrc                   -> $(SEC_CONFIG) ;
        /root/.bashrc                   -> $(SEC_CONFIG) ;
        /root/.bash_profile             -> $(SEC_CONFIG) ;
        /root/.bash_logout              -> $(SEC_CONFIG) ;
        /root/.bash_history             -> $(SEC_CONFIG) ;
        #/root/.amandahosts             -> $(SEC_CONFIG) ;
        #/root/.addressbook.lu          -> $(SEC_CONFIG) ;
        #/root/.addressbook             -> $(SEC_CONFIG) ;
        #/root/.Xresources              -> $(SEC_CONFIG) ;
        #/root/.Xauthority              -> $(SEC_CONFIG) -i ; # Changes Inode number on login
        #/root/.ICEauthority            -> $(SEC_CONFIG) ;
```

Casi terminado. Como teníamos varios reclamos sobre algunos descriptores de archivos en el sistema de archivos /proc, y estos ficheros cambian todo el tiempo, para evitar falsos positivos regularmente, eliminaremos la comprobación específica sobre la carpeta general /proc, y añadiremos todos los directorios de /proc que si queremos que se comprueben.

Ves a la sección "Devices & Kernel information" y haz lo siguiente:

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

Y lo último, necesitamos comentar las líneas /var/run y /var/lock para que no señale los cambios normales del sistema de archivos por servicios:

```bash
        #/var/lock              -> $(SEC_CONFIG) ;
        #/var/run               -> $(SEC_CONFIG) ; # daemon PIDs
        /var/log                -> $(SEC_CONFIG) ;
```

¡HECHO! Con tripwire configurado, primero recreamos su política encriptada:

```bash
twadmin -m P /etc/tripwire/twpol.txt
```

y reiniciamos la base de datos:

```bash
tripwire --init
```

Si todo ha ido bien, no tendremos advertencias, así que activamos un chequeo:

```bash
tripwire --check
```

Allá vamos, éste será un informe típico del tripwire.

Vamos a limpiar el sistema de información confidencial:

```bash
rm /etc/tripwire/test_results
rm /etc/tripwire/twpol.txt
```

Sólo en el caso de que algún día tengamos que editar de nuevo la configuración tripwire, tendremos que recrear temporalmente el archivo de texto plano que acabamos de editar:

```bash
sh -c 'twadmin --print-polfile > /etc/tripwire/twpol.txt'
```


Así es como lo hacemos!

Estamos cerca del final de la historia, solo necesitamos configurar la notificación de correo de tripwire y, como hicimos para rkhunter, automatizar los chequeos con CRON:

```bash
tripwire --check | mail -s "Tripwire report for `uname -n`" your@email
```

Esto generará un informe tripwire y lo enviará al correo especificado. ¡Solo con esto!
Después, añadimos un nuevo trabajo-cron a la tabla cron:

```bash
crontab -e
```

y añadimos esta línea:

```bash
30 03 * * * /usr/sbin/tripwire --check | mail -s "Tripwire report for `uname -n`" your@email
```

Así, todos los días recibiremos un informe de **tripwire**, y otro de **rkhunter** en caso de encontrar algunas advertencias.

Pero esto supone un montón de registros e informes, por lo que vamos a instalar un analizador de registro muy poderoso para ayudarnos a organizar y recuperar información sobre nuestro sistema, por lo que la siguiente historia, corta, es Logwatch Log Analyzer!

### Logwatch Log Analyzer

Por lo general, los archivos de registro del sistema son realmente, realmente, archivos largos con eventualmente una gran cantidad de información repetida, por lo que con el fin de ayudarnos a mantener nuestro hermoso servidor raspbian, vamos a instalar aquí una aplicación muy útil que toma todos los registros del sistema y crea uno limpio y agradable de digerir acerca de las actividades del sistema (las buenas y las no tan buenas), así que vamos a instalar logwatch:

```bash
apt-get install logwatch
```

¡Hecho! Ahora, como siempre, tenemos que editar su archivo de configuración:

```bash
nano /usr/share/logwatch/default.conf/logwatch.conf
```

Y edita la línea **MailTo**, poniendo la dirección de correo en la que deseas que logwatch envíe los informes:

```bash
MailTo = email@address
```

¡Y eso es todo! Ahora tenemos un informe diario perfectamente legible generado automáticamente por logwatch, ¡genial!

Si deseas probarlo desde el terminal para echar un vistazo a los informes, simplemente escribe:

```bash
logwatch --detail High --mailto email@address
```

Espera un poco y revisa tu correo, ¡ahí está!

El servidor está casi preparado y razonablemente asegurado, estamos en los últimos pasos de nuestro viaje, solo necesitaremos asegurar apache con un certificado TLS/SSL de Let's Encrypt, luego configurar nuestros nombres de host que vamos a alojar y finalmente, configurar correctamente y con seguridad nuestro router casero para tener el servidor Raspbian asombroso disponible en Internet !!!!

Siguiente historia, certificados TLS/SSL.

### TLS/SSL

Los certificados SSL se utilizan en servidores web para encriptar el tráfico entre el servidor y el cliente, proporcionando una mayor seguridad a los usuarios que acceden a su aplicación. Let's Encrypt proporciona una manera fácil de obtener e instalar certificados de confianza de forma gratuita.

Recuerda que para completar este paso, necesitas tener configurado ya algún dominio (www.yourdomain.com) con los DNS apuntando a tu servidor principal (tu dirección IP doméstica).

Así que vamos a instalar y configurar nuestro servidor apache con un certificado TLS/SSL de [Let's Encrypt](https://letsencrypt.org/), vamos a hacerlo:

```bash
apt-get install augeas-lenses libaugeas0
apt-get install -t stretch python-certbot-apache
```

Ahora configura el certificado SSL:

```bash
certbot --apache
```

Esto será realmente sencillo, el mecanismo certbot hará todo el trabajo, responde a sus preguntas y lo tendrás!

Ahora intenta conectar con https://www.tudominio.elquesea y ya está, el certificado SSL activo y funcionando

Ahora, vamos a encriptar los certificados que necesitan renovarse cada 90 días, así que lo mejor es automatizar el chequeo para la renovación con un cronjob, abre tu crontab:

```bash
crontab -e
```
y añade esta línea (personaliza el tiempo a tu gusto)

```bash
00 4 * * 1 /usr/bin/certbot renew >> /var/log/le-renewal.log
```

Esa línea significa, chequea cada lunes a las 04:00 h si es necesario renovar los certificados de encriptación, y si ese es el caso, renuévalos. ¡Fácil!

Lo tenemos, nuestro servidor está casi completo, la próxima historia, HARDENING!


## HARDENING (BONUS)

Deshabilita el Kernel hardening y también IPv6, para ello edita el archivo /etc/sysctl.conf y añade/edita:

```bash
# Turn on execshield
kernel.exec-shield=1
kernel.randomize_va_space=1
...
# Disable tcp timestamps
net.ipv4.tcp_timestamps = 0
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

Guárdalo y después abre el archivo /etc/default/ntp y haz lo que ves aquí:

```bash
NTPD_OPTS='-4 -g'
```

Reinicia y disfruta!


## CONFIGURACIÓN DEL ROUTER DE CASA

Para estar disponible en Internet, necesitaremos abrir un puerto específico para cada uno de los servicios que queramos ofrecer a los usuarios. En casa tenemos nuestro fantástico Servidor Raspbian conectado a Internet DETRÁS de nuestro router; aunque el servidor esté perfectamente configurado con su cortafuegos, el router está, por defecto, completamente cerrado para las conexiones de entrada, lo que implica que no permitirá a nadie alcanzar nuestra página web en el puerto 80 (http) o el puerto 443 (https), porque cuando le pidamos alguno de esos accesos, nuestro router negará el paso. Esto es realmente positivo, porque si el router estuviera completamente abierto, probablemente nuestra conexión a Internet quedaría desbordada enseguida.

Así que, recuerda, cada puerto que abras en tu router, significa disponibilidad, pero también exposición, por eso estamos intentando construir un servidor bastante seguro.

Con esto claro, tendremos que acceder a la configuración del router, que generalmente está en la ip 192.168.1.1 (pero no siempre, revisa el manual de tu router), y en la sección firewall, o en la sección de reenvío de puertos (depende del modelo del router), tendremos que abrir el puerto para nuestro servidor específico, por ejemplo, si queremos activarlo como servidor web, tendremos que reenviar el puerto 80 al puerto 80 de nuestro Raspbian (apuntando a la ip interna LAN del Servidor), y lo mismo para el puerto 443.
O, si queremos acceder a través de SSH desde Internet, tendremos que reenviar el puerto de entrada 22 al puerto 22 de la IP interna LAN del servidor.

Lo mismo para cualquier otro servicio que necesites.

Así que hazlo, y luego prueba tus servicios, si todo esta correcto, tu servidor está realmente DISPONIBLE!!! ¡Enhorabuena!


## Tu servidor dedicado de 80€ (80DS)

Esta es la línea de meta, lo hemos hecho, pero antes de decir adiós, vamos a dar el paso final, un paso que un buen administrador de sistema debería repetir al menos una vez por semana:

1 - Buscar actualizaciones y aplicar

```bash
apt-get update && apt-get dist-upgrade
```

2 - Actualizar rkhunter

```bash
rkhunter --propupd
```

3 - Actualizar tripwire

```bash
tripwire --init
```

4 - Hora de irse, nuestro Raspbian Server está rock n rollin'.

Finalmente, a modo de conclusiones, podemos decir que este viaje no ha sido tan fácil, ni siempre cómodo, pero maldita sea, fue aventurero, ¿no? Así, como en la recurrente comparación entre turistas y viajeros, esto ha sido ciertamente una historia de viajeros.
