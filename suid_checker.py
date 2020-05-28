#!/usr/bin/env python
# This tool searches the system for SUID files, it checks to see if they are known good,
# or checks for known bad, and then checks to see if there is a MAN page for that command
# if not MAN page, then a higher chance this maybe a bespoke SUID which might be exploitable!!

import os
import subprocess


# Below is a list if common SUID found on systems, it is not a full list!! needs improving...
allow = ['/usr/bin/gpasswd','/bin/mount','/usr/bin/pkexec','/bin/ntfs-3g','/usr/sbin/exim4','/usr/sbin/pppd','/sbin/mount.nfs','/usr/lib/openssh/ssh-keysign','/usr/lib/dbus-1.0/dbus-daemon-launch-helper','/usr/lib/xorg/Xorg.wrap','/usr/lib/policykit-1/polkit-agent-helper-1','/usr/lib/eject/dmcrypt-get-device','/usr/bin/passwd','/bin/umount','/usr/bin/chfn','/usr/bin/newgrp','/usr/bin/chsh','/usr/bin/vmware-user-suid-wrapper','/usr/bin/bwrap','/usr/bin/sudo','/bin/fusermount','/bin/ping','/bin/su','/sbin/mount.cifs']

# Below is files that could be dangerous to be SUID.. these are used to break out of restrict shells.. more info, https://gtfobins.github.io
priv = ['apt-get','apt','ash','awk','bash','busybox','cpan','cpulimit','csh','dash','easy_install','ed','emacs','env','expect','facter','find','flock','ftp','gdb','git','ionice','jjs','journalctl','jrunscript','ksh','ld.so','less','ltrace','lua','mail','make','man','more','mysql','nano','nice','nmap','node','perl','pg','php','pic','pip','puppet','python','rlwarp','rpm','rpmquery','rsync','ruby','run-mailcap','run-parts','rvim','scp','sed','setarch','sftp','smbclient','sqlite3','ssh','start-stop-daemon','stdbuf','strace','tar','taskset','tclsh','telnet','time','timeout','unshare','vi','vim','watch','wish','xargs','zip','zsh']

# Seaches for SUID files
proc = subprocess.Popen(["find","/","-perm","-u=s","-type","f"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

for line in proc.stdout:
	line = line.rstrip()
	if line not in allow:
		line1 = line.split("/")[-1]
		if line1 in priv:
			print "[<*>] HIGH CHANCE OF PRIV ESC: "+line
		else:
			s_check = subprocess.Popen(["man","-k",line1], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			o1 = s_check.communicate()[1]
			if "nothing" in o1:
				print "[<*>] Does not have MAN entry.. possible not default linux command: "+line
			else:
				print "[*] "+line1+" has a MAN entry, but not part of the common list of SUIDs :"+line

