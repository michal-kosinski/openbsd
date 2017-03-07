<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN"
  "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
	
<?

$filename = 'index.php';
          if (file_exists($filename))
                 echo "<title>OpenBSD " . date ("Y.m.d", filemtime($filename)) ."</title>";
?>
	
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	<meta http-equiv="Pragma" content="no-cache" />
  <link rel="stylesheet" type="text/css" href="style.css" />
</head>

<body>
	
<pre>
# pkg_info
GeoIP-1.6.5p2       find the country where IP address/hostname originates from
bash-4.3.42         GNU Bourne Again Shell
bzip2-1.0.6p7       block-sorting file compressor, unencumbered
cdrtools-3.00p1     ISO 9660 filesystem and CD/DVD/BD creation tools
cmatrix-1.2ap0      scrolling 'Matrix'-like screen
fping-3.13          quickly ping N hosts w/o flooding the network
git-2.7.0           GIT - Tree History Storage Tool
hping-2.0.0rc3p4    TCP/UDP ping/traceroute tool
ifstat-1.1p4        tool to monitor interface bandwidth usage
lsof-4.89           list information about open files
lynx-2.8.9pl8p1     text web browser
mc-4.8.15p0         free Norton Commander clone with many useful features
mrtg-2.17.4p3       multi-router traffic grapher
nmap-7.01           scan ports and fingerprint stack of network hosts
nut-2.7.3p2         UPS monitoring program supporting many brands
rsync-3.1.2         mirroring/synchronization over low bandwidth links
screen-4.0.3p6      multi-screen window manager
sshfs-fuse-2.5      mount remote directories over ssh
tree-0.62           print ascii formatted tree of a directory structure
unzip-6.0p9         extract, list & test files in a ZIP archive
vim-7.4.900-no_x11  vi clone, many additional features
wget-1.16.3p0       retrieve files from the web via HTTP, HTTPS and FTP
xz-5.2.2p0          LZMA compression and decompression tools

# pkg_add -vi \
GeoIP \
bash \
bzip2 \
cdrtools \
cmatrix \
fping \
git \
hping \
ifstat \
lsof \
lynx \
mc \
mrtg \
nmap \
nut \
rsync \
screen \
sshfs-fuse \
tree \
unzip \
vim \
wget \
xz
</pre>

<pre>
# cat /root/.profile
alias hexe="ssh -Cv mkosinski@77.253.208.171"

echo "ssh-bruteforce entries: `pfctl -t ssh-bruteforce -T show|wc -l|awk '{print $1}'`"
echo "blocked IP zones: `wc -l /etc/pf-files/blocked_zones|awk '{print $1}'`"
echo ; for x in `pfctl -t ssh-bruteforce -T show` ; do geoiplookup $x ; done|awk -F, '{print $2}'|sort|uniq -c|sort -nr|grep -v "^   1"
#pfctl -t ssh-bruteforce -T expire 86400
#pfctl -t ssh-bruteforce -T delete 218.70.0.0/16

echo ; gzcat  /var/log/authlog*gz|grep "Failed password for root"|awk '{print $11}'|sort|uniq -c|sort -nr|head -10
echo ; netstat -an|grep "^tcp "|awk '{print $6}'|sort|uniq -c
echo ; upsc apc@localhost |egrep "battery.charge:|battery.voltage:|ups.load:"

cmatrix

# cat /etc/profile
export PKG_PATH="http://ftp.task.gda.pl/pub/OpenBSD/`uname -r`/packages/`machine -a`/"
echo "OpenBSD 4.7 release in `/usr/local/bin/<a href="openbsd.pl.txt">openbsd.pl</a>` :-)\n"
mesg n ; uname -a ; w ; echo ; df -hi ; echo ; quota -v
</pre>

<pre>
# pkg_add -vi mrtg
# mkdir -p /var/www/htdocs/mrtg

# cfgmaker \
--global 'WorkDir: /var/www/htdocs/mrtg' \
--global 'Options[_]: growright' \
--global 'WithPeak[_]: ymw' \
--global 'XSize[_]: 600' \
--global 'YSize[_]: 150' \
--global 'YTics[_]: 5' \
--global 'Suppress[_]: y' \
--output /etc/mrtg.cfg \
public@localhost

# indexmaker /etc/mrtg.cfg > /var/www/htdocs/mrtg/index.html

# crontab -l|grep mrtg
*/5     *       *       *       *       /usr/local/bin/mrtg /etc/mrtg.cfg 2>/dev/null
</pre>

<pre>
lynx -dump "http://pgl.yoyo.org/adservers/serverlist.php?showintro=0&hostformat=hosts" >> /etc/hosts
lynx -dump "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist" >> /etc/zeus.txt
</pre>

<pre>
tcpdump -onvvXe -i fxp0 port ! 22 and host ! 94.23.90.238
</pre>

<pre>
# cat /etc/hostname.*
dhcp description WAN
inet 172.16.10.254 255.255.255.0 NONE description LAN

# cat hostname.pppoe0
inet 0.0.0.0 255.255.255.255 NONE \
pppoedev fxp0 authproto pap \
authname '' authkey '' up
dest 0.0.0.1
!/sbin/route add default -ifp pppoe0 0.0.0.1
</pre>

<pre>
# cat /etc/pf.conf
#       $OpenBSD: pf.conf,v 1.53 2014/01/25 10:28:36 dtucker Exp $
#
# See pf.conf(5) for syntax and examples.
# Remember to set net.inet.ip.forwarding=1 and/or net.inet6.ip6.forwarding=1
# in /etc/sysctl.conf if packets are to be forwarded between interfaces.

# increase default state limit from 10'000 states on busy systems
#set limit states 100000

ext_if="fxp0"
int_if="em0"

ext_ip = "87.207.235.78"
int_ip = "192.168.0.2"

#pass on $ext_if from $int_ip to any binat-to $ext_ip
#pass on $ext_if from $ext_ip to any binat-to $int_ip

table <ssh-bruteforce> persist
table <zeus> const file "/etc/pf-files/zeus"
table <blocked_zones> persist file "/etc/pf-files/blocked_zones"
table <trusted> { 172.16.10/24, 213.135.44/22, 212.2.96/19, 37.247.128/17  } const

set skip on lo

match out on $ext_if from $int_if:network nat-to ($ext_if)
#match in on $ext_if proto tcp to ($ext_if) port 8080 rdr-to 172.16.10.253 # tomato

# filter rules and anchor for ftp-proxy(8)
anchor "ftp-proxy/*"
pass in quick inet proto tcp to port ftp divert-to 127.0.0.1 port 8021

block return    # block stateless traffic
pass            # establish keep-state

# By default, do not permit remote connections to X11
block return in on ! lo0 proto tcp to port 6000:6010

pass in quick from <trusted>

block in quick inet6 all
block in quick from <ssh-bruteforce>
block in quick from <zeus>
block in quick from <blocked_zones>
block in quick proto tcp from ! <trusted> to port { 80, 443 }

pass in inet proto tcp to port ssh flags S/SA keep state (max-src-conn 100, max-src-conn-rate 2/60, overload <ssh-bruteforce> flush global)
</pre>

<pre>
# cat /etc/pf-files/update.sh

#!/bin/sh

DIR="/etc/pf-files"
CC="cn az by kz kg ru tj tm uz vn"

mv $DIR/blocked_zones $DIR/blocked_zones.bak
mv $DIR/zeus $DIR/zeus.bak

for x in $CC
   do
        echo "Downloading ${x}.zone file"
        wget -q -4 --no-proxy --no-cookies --no-cache http://ipdeny.com/ipblocks/data/countries/${x}.zone -O $DIR/${x}.zone
        sleep 1
        cat ${x}.zone >> $DIR/blocked_zones
   done

echo "Downloading ZeuS IP blocklist"
wget -q -4 --no-proxy --no-cookies --no-cache \
https://zeustracker.abuse.ch/blocklist.php?download=badips -O $DIR/zeus

if [ ! -s $DIR/blocked_zones ]; then
        echo "Download NOT complete."
        exit 1
fi

if [ ! -s $DIR/zeus ]; then
        echo "Download NOT complete."
        exit 1
fi


echo "Download complete, reloading pf ruleset"
pfctl -nf /etc/pf.conf
echo "Done."
</pre>

<pre>
# grep -v ^# /etc/sysctl.conf
net.inet.ip.forwarding=1        # 1=Permit forwarding (routing) of IPv4 packets
ddb.panic=0                     # 0=Do not drop into ddb on a kernel panic
machdep.kbdreset=1              # permit console CTRL-ALT-DEL to do a nice halt
hw.setperf=1
</pre>

<pre>
# cat /etc/rc.conf.local
dhcpd_flags=
ftpproxy_flags=
httpd_flags=
ntpd_flags=
pkg_scripts=upsd upsmon
sndiod_flags=NO
snmpd_flags=
unbound_flags=
</pre>

<pre>
# cat /etc/fstab
/dev/wd0a / ffs rw,noatime,softdep 1 1
/dev/wd0e /home ffs rw,noatime,softdep,nodev,nosuid 1 2
/dev/wd0d /tmp ffs rw,noatime,softdep,nodev,nosuid 1 2
</pre>

<pre>
# grep fsck /etc/rc
# shell catches SIGQUIT (3) and returns to single user after fsck.
        fsck -p -y
</pre>

<pre>
# echo boot > /etc/boot.conf
</pre>

<pre>
# cat /etc/rc.local
date >> /var/log/reboot.log
</pre>

<pre>
# cat /etc/fstab
/proc /proc procfs rw,linux 0 0

# grep linux /etc/sysctl.conf
#kern.emul.linux=1              # enable running Linux binaries

pkg_add -vi fedora_base

echo "/proc /proc procfs rw,linux 0 0" >> /etc/fstab
mkdir /proc && mount /proc && sysctl -w kern.emul.linux=1

rpm2cpio *.rpm|cpio -vid
</pre>

<pre>
# grep -v ^# /etc/ssh/sshd_config
Port 22
Port 443
AddressFamily inet

# grep -v ^# /etc/ssh/ssh_config
HashKnownHosts yes
VisualHostKey yes
</pre>

<pre>
chflags schg /bsd
chflags schg /etc/changelist
chflags schg /etc/daily
chflags schg /etc/inetd.conf
chflags schg /etc/netstart
chflags schg /etc/pf.conf
chflags schg /etc/rc
chflags schg /etc/rc.conf
chflags schg /etc/rc.local
chflags schg /etc/rc.securelevel
chflags schg /etc/rc.shutdown
chflags schg /etc/security
chflags schg /etc/mtree/special

chflags -R schg /bin
chflags -R schg /sbin
chflags -R schg /usr/bin
chflags -R schg /usr/libexec
chflags -R schg /usr/sbin
</pre>

<pre>
cd /usr && cvs -z6 -danoncvs@anoncvs.ca.openbsd.org:/cvs co -rOPENBSD_4_6 ports
cd /usr/src && cvs -z6 -danoncvs@anoncvs.ca.openbsd.org:/cvs co -rOPENBSD_4_6 sys

cp /bsd /bsd.old
cd /usr/src/sys/arch/i386/conf/
config GENERIC
cd /usr/src/sys/arch/i386/compile/GENERIC/
make clean && make depend && make && make install

option  WS_KERNEL_FG=WSCOL_WHITE	# set foreground white
option  WS_KERNEL_BG=WSCOL_RED		# set background black

root on nfs swap on nfs
</pre>

<pre>
PXE:
rarpd_flags="-a"        # for normal use: "-a"
bootparamd_flags=""     # for normal use: ""
nfs_server=YES          # see sysctl.conf for nfs client configuration
portmap=YES             # Note: inetd(8) rpc services need portmap too
inetd=YES               # almost always needed

NFS:
nfs_server=YES          # see sysctl.conf for nfs client configuration
portmap=YES             # Note: inetd(8) rpc services need portmap too
</pre>

<pre>
#
# This is PXE (Preboot Execution Environment) boot from network with NFS filesystem example for OpenBSD
#
# server name: gumis (172.16.10.254)
# client name: sbox  (172.16.10.100)
# NFS root for sbox: /exports/sbox/root
# NFS swap for sbox: /exports/sbox/swap

1. egrep "bootparamd_flags|dhcpd|nfs|rarpd|portmap|inetd" /etc/rc.conf
rarpd_flags="-a"        # for normal use: "-a"
bootparamd_flags=""     # for normal use: ""
dhcpd_flags=""          # for normal use: ""
nfs_server=YES          # see sysctl.conf for nfs client configuration
portmap=YES             # Note: inetd(8) rpc services need portmap too
inetd=YES               # almost always needed
nfsd_flags="-tun 4"	# Crank the 4 for a busy NFS fileserver

2. grep tftp /etc/inetd.conf
tftp            dgram   udp     wait    root    /usr/libexec/tftpd      tftpd -s /tftpboot

3.
cd /usr/src/sys/arch/i386/conf && config DISKLESS && cd ../compile/DISKLESS && make depend bsd && cp bsd /tftpboot/bsd

4. ls -l /tftpboot
-rw-r--r--  1 root  wheel  3501571 Feb 21 22:14 bsd
-rw-r--r--  1 root  wheel    53848 Sep 17  2004 pxeboot

5. cat /etc/exports
/exports/sbox    -maproot=root   -alldirs        -network 172.16.10    -mask 255.255.255.0
/exports/sbox    -maproot=root   -alldirs        sbox

6.
wget -r -np http://ftp.sunet.se/pub/OpenBSD/4.6/i386/
for a in {base,etc}*.tgz ; do gtar zxfp $a -C /exports/sbox/root ; done
dd if=/dev/zero of=/exports/sbox/swap bs=256k count=1024

7. ls -l /exports/sbox
drwxr-xr-x  14 root  wheel        512 Feb 21 16:32 root
-rw-r--r--   1 root  wheel  268435456 Feb 21 16:34 swap

8. cat /etc/bootparams
sbox root=gumis:/exports/sbox/root swap=gumis:/exports/sbox/swap

9. cat /etc/ethers
00:08:9b:9b:77:e6 172.16.10.100

10. cat /etc/hosts
127.0.0.1			localhost
172.16.10.254	gumis
172.16.10.100	sbox

11. cat /etc/dhcpd.conf
host sbox
{
        hardware ethernet 00:08:9b:9b:77:e6;
        fixed-address 172.16.10.100;
        next-server 172.16.10.254;
        option host-name "sbox";
        filename "pxeboot";
        option root-path "172.16.10.254:/exports/sbox/root";
}

12. cat /exports/sbox/root/etc/fstab
gumis:/exports/sbox/root /       nfs     rw,tcp,soft,intr      0       0

rw            mount filesystem read-write
ro            mount filesystem read-only
bg            if mount fails, keep trying in the background
hard          if server goes down, make operations accessing it BLOCK
soft          if server goes down, allow operations accessing it to FAIL with an error
retrans=N     number of times to retry request before FAILING (must also specify 'soft')
timeo=N       timeout period for a given request (in TENTHS of seconds)
intr          allow users to INTERRUPT blocked requests (making then return an error)
rsize=N       set the read buffer size (in bytes)
wsize=N       set the write buffer size (in bytes)

13. cat /exports/sbox/root/etc/myname
sbox

14. cat /exports/sbox/root/etc/hostname.rl0
inet 172.16.10.100 255.255.255.0 NONE

15. cat /exports/sbox/root/etc/hosts
127.0.0.1			localhost
172.16.10.254	gumis
172.16.10.100	sbox

16. rpcinfo -p
   program vers proto   port
    100000    2   tcp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp    660  mountd
    100005    3   udp    660  mountd
    100005    1   tcp    752  mountd
    100005    3   tcp    752  mountd
    100003    2   udp   2049  nfs
    100003    3   udp   2049  nfs
    100003    2   tcp   2049  nfs
    100003    3   tcp   2049  nfs
    100026    1   udp    614  bootparam

17. debug :-)
grep 50 /usr/src/sys/sys/errno.h
grep 52 /usr/src/sys/sys/errno.h
</pre>

<pre>
select lines 14 through 30 of file

         awk 'NR==14, NR==30' file

all lines between BEGIN and END lines (you can substitute any strings for
BEGIN and END, but they must be between slashes)

         awk '/BEGIN/,/END/' file

print 3rd field from each line, but the colon is the field separate

         awk -F: '{print $3}' file

Print out the last field in each line, regardless of how many fields:

         awk '{print $NF}' file

To print out a file with line numbers at the edge:

         awk '{print NR, $0}' somefile

This is less than optimal because as the line number gets longer in digits,
the lines get shifted over.  Thus, use printf:

         awk '{printf "%4d %s\n", NR, $0}' somefile
</pre>

<pre>
perl -MCPAN -e shell

#!/usr/bin/perl

use ExtUtils::Installed;
my $instmod = ExtUtils::Installed->new();
foreach my $module ($instmod->modules()) {
my $version = $instmod->version($module) || "???";
       print "$module -- $version\n";
}
</pre>

<pre>
# cat /home/backup/backup.sh

#!/bin/sh

DIR="/home/backup"

find $DIR -name "*.gz" -mtime +14 -exec rm -f {} \;

crontab -l > /etc/backup-crontab.txt
pkg_info > /etc/backup-pkg_info.txt

tar zcf $DIR/`uname -n|awk -F. '{print $1}'`_etc_`date "+%Y%m%d"`.tar.gz \
        /etc \
        /var/www/conf \
        /var/www/htdocs \
        /root/.ssh \
        /root/*.sh \
        /root/*.txt \
        /root/.* \
        /home/backup/backup.sh \
        /var/log/*.log \
        /var/unbound/etc \
        /usr/local/bin/openbsd.pl
</pre>

<pre>
# cat make_boot_cd.sh
#!/bin/sh
#
## Calomel.org -- Making a bootable OpenBSD CD
## calomel_make_boot_cd.sh
#
arch="i386"       # Architecture
version="5.9"      # OS version
#
echo "building the environment"
rm -rf /root/OpenBSD
mkdir -p /root/OpenBSD/$version/$arch
cd /root/OpenBSD/$version/$arch
#
echo "getting the release files"
#wget -T5 -l0 -c --passive-ftp --reject "comp*,floppy*,*iso,*fs,x*tgz,misc*,game*" http://ftp.openbsd.org/pub/OpenBSD/$version/$arch/*
wget -T5 -l0 -c --passive-ftp --reject "comp*,floppy*,*iso,*fs,x*tgz,misc*,game*" ftp://ftp.icm.edu.pl/pub/OpenBSD/$version/$arch/*
echo "checking sha1 checksums"
cd /root/OpenBSD/$version/$arch
egrep -v "x|game|iso|floppy|comp|misc" SHA256 > SHA256.tmp
sha1 -c SHA256.tmp
rm -f SHA256.tmp
#
echo "building the ISO"
cd /root/OpenBSD
time mkisofs -r -no-emul-boot -b $version/$arch/cdbr -c boot.catalog -o /root/OpenBSD-$version-small.iso /root/OpenBSD/
ls -l /root/OpenBSD-$version-small.iso
#
echo "DONE."
</pre>

<pre>
# vnconfig svnd0 /tmp/ISO.image
# mount -t cd9660 /dev/svnd0c /mnt
# umount /mnt
# vnconfig -u svnd0
</pre>

<pre>
# cat /etc/arp.permanent
82.210.147.254 00:0e:d6:be:2c:8c permanent

# cat /etc/rc.local
if [ -s /etc/arp.permanent ]; then
        /usr/sbin/arp -d -a
        /usr/sbin/arp -f /etc/arp.permanent
fi
</pre>

<pre>
# cat /etc/syslog-ng/syslog-ng.conf

source net { udp(ip(0.0.0.0) port(514)); };

destination cisco {
        file ("/var/log/cisco/$HOST/$YEAR-$MONTH/$HOST-$YEAR-$MONTH-$DAY-$FACILITY.log"
                owner(root) group(wheel) perm(0600) dir_perm(0700) create_dirs(yes)
        );
};

log { source(net); destination(cisco); };
</pre>

<pre>
# cat /etc/squid/squid.conf
http_port 127.0.0.1:3128
cache_dir null /tmp

--enable-storeio=null
</pre>

<pre>
$ openssl s_client -connect localhost:993
$ openssl x509 -text -in cert.pem
$ echo|openssl s_client -connect localhost:993 2>/dev/null |sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' |openssl x509 -text
</pre>

<pre>
# tar -cXf - . | tar -xpf - -C /mnt/raid
</pre>

<pre>
# cat .vimrc

syntax on
set autoindent
set number
set hlsearch
set incsearch
set background=dark
set mouse=a
set ignorecase
set fileformat=unix
</pre>

<pre>
&lt;Directory /var/www/htdocs/files&gt;
	Order allow,deny
	allow from all
	Options +Indexes
	IndexIgnore .. .* *.sh
	IndexOptions +FancyIndexing +Charset=UTF-8 +NameWidth=100 +SuppressDescription +IgnoreCase
&lt;/Directory&gt;
</pre>

<pre>
git clone /opt/projects/x ./x
git config core.sparsecheckout true
git read-tree -m -u HEAD
git pull
</pre>

<pre>
# cat /var/unbound/etc/unbound.conf
server:
        interface: 172.16.10.254
        access-control: 172.16.10.0/24 allow
        access-control: 127.0.0.1 allow
        verbosity: 1
        do-ip6: no
        do-tcp: no
        hide-identity: yes
        hide-version: yes

        local-zone: "doubleclick.net" redirect
        local-data: "doubleclick.net A 127.0.0.1"
        local-zone: "googlesyndication.com" redirect
        local-data: "googlesyndication.com A 127.0.0.1"
        local-zone: "googleadservices.com" redirect
        local-data: "googleadservices.com A 127.0.0.1"
        local-zone: "google-analytics.com" redirect
        local-data: "google-analytics.com A 127.0.0.1"
        local-zone: "ads.youtube.com" redirect
        local-data: "ads.youtube.com A 127.0.0.1"
        local-zone: "adserver.yahoo.com" redirect
        local-data: "adserver.yahoo.com A 127.0.0.1"

forward-zone:
      name: "."
      forward-addr: 8.8.8.8        # Google Public DNS
      forward-addr: 8.8.4.4        # Google Public DNS

remote-control:
        control-enable: no
</pre>

<pre>
echo "LESS = -i -R -n" > ~/.lesskey ; lesskey
</pre>

<pre>
@echo off
D:\Tools\pskill -t chrome.exe
ping -n 5 127.0.0.1
start "" "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --restore-last-session --disable-session-crashed-bubble --disk-cache-dir="Z:\" --media-cache-dir="Z:\"
exit	
</pre>

<pre>
# grep _ups /etc/group
dialer:*:117:_ups
_ups:*:529:

# cat /etc/nut/ups.conf
[apc]
        driver = apcsmart
        port = /dev/tty00
        desc = "APC BACK-UPS PRO 650"

# cat /etc/nut/upsmon.conf
MONITOR apc@localhost 1 upsmon pass master

# cat /etc/nut/upsd.users
[admin]
        password = pass
        actions = SET
        instcmds = ALL

[upsmon]
        password = pass
        upsmon master

# rcctl enable upsd
# rcctl enable upsmon

</pre>

<pre>
https://github.com/wimg/PHPCompatibility

php-simplexml
php-tokenizer
php-xmlwriter

pear channel-update pear.php.net
pear install --onlyreqdeps PHP_CodeSniffer
cd /usr/share/pear/PHP/CodeSniffer/Standards && git clone https://github.com/wimg/PHPCompatibility.git

vi /usr/share/pear/PHP/CodeSniffer/Standards/PHPCompatibility/composer.json

"require-dev": {
   "squizlabs/php_codesniffer": "*",
   "wimg/php-compatibility": "*",
   "simplyadmire/composer-plugins" : "@dev",
   "prefer-stable" : true
},

$ grep memory_limit /etc/php5/php.ini
memory_limit = 512M

$ grep timezone /etc/php5/php.ini
date.timezone = Europe/Warsaw

--exclude=PHPCompatibility.PHP.DefaultTimeZoneRequired

phpcs --standard=PHPCompatibility --severity=ERROR --runtime-set testVersion 5.3-5.5 test.php
</pre>

</body>
</html>
