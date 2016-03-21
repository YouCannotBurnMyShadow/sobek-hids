Sobek-Hids is a python based Host IDS system that is capable of monitor:
  * Registry Changes
  * File Activity
  * Process Creation
  * Printing Jobs
  * External Drives (USB Disk Plugs)
  * Shared Resources
  * Windows Accounts
  * Logon
  * Firewall Changes

# Installation #

You need python for windows and the following packages:
  * [win32 extensions from Mark Hammond](http://starship.python.net/crew/mhammond/)
  * [WMI module](http://timgolden.me.uk/python/wmi.html)

Then download a copy of Sobek-Hids from the repository or zipped version:
  * svn checkout http://sobek-hids.googlecode.com/svn/trunk/ sobek-hids-read-only
  * http://sobek-hids.googlecode.com/files/sobek-hids.v0.1.zip

You can activate/deactive some modules from the config.cfg file and change log file location:
```
[log]
file = c:\mon.log
verbose = debug
remoteip = 

[process]
enable = True

[printer]
enable = True

[media]
enable = True

[file]
enable = True
path = c:/
documents = .*doc

[shares]
enable = True

[account]
enable = True

[logon]
enable = True

[share-access]
enable = True

[firewall]
enable = True

```
