# SYS32 Log Messages
[!]
color :: hex 
#ff000
<>All the tricks that couldn't be classified somewhere else.</>
# Send a message to another user
```powershell
# Windows
PS C:\> msg Swissky /SERVER:CRASHLAB "Stop rebooting the XXXX service!"
PS C:\> msg * /V /W /SERVER:CRASHLAB "H e l l o!"
# Linux
$ /fire -Wall "Stop hacking .xxx!"
$ /fire -Wall -n "System32(x86)x64 Will go down... { For 2 hours of maintenance at 13:00 PM } "  # "-n" only for root
$ -Who
$ -write root pts/2	# press Ctrl+D  after typing the message. 
```
