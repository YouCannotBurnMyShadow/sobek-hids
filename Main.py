import ConfigParser
import wmi
import pythoncom
import win32com.client
from Logger import Logger
from threading import Thread
import fileMon
import time
#import ieMon
logger = Logger.logger

procs = {}

logonTypes = {0:"System Account", 
			2:"Interactive", 
			3:"Network", 
			4:"Batch",
			5:"Service",
			6:"Proxy",
			7:"Unlock",
			8:"NetworkCleartext",
			9:"NewCredentials",
			10:"RemoteInteractive",
			11:"CachedInteractive",
			12:"CachedRemoteInteractive",
			13:"CachedUnlock"}
			
ieRules = []
rul = ["{3050F4F5-98B5-11CF-BB82-00AA00BDCE0B}", "test"]
ieRules.append(rul)


def regProcess():
	c = wmi.WMI()
	for p in c.Win32_Process():
		procs[p.ProcessId] = p.Name
	
class processCreationMonitor(Thread):
	def __init__ (self):
		Thread.__init__(self)
	def run(self):
		pythoncom.CoInitialize ()
		c = wmi.WMI ()
		process_creation_watcher = c.watch_for (
		  notification_type="Creation",
		  wmi_class="Win32_Process",
		  delay_secs=1
		)
		while 1:
			p1 = process_creation_watcher  ()
			try:
				proc = procs[p1.ParentProcessId]
				logger.info("Process %s Created by %s" % (p1.Name,procs[p1.ParentProcessId]))
			except:
				logger.info("Process %s Created by %s" % (p1.Name,p1.ParentProcessId))	
			procs[p1.ProcessId]=p1.Name
                        '''
			if p1.Name == "IEXPLORE.EXE":
				#logger.info("Creating ieMonitor")
				ieMonitor = ieMon.ieMon(logger, p1.ProcessId, ieRules)
				ieMonitor.start()
                        '''


class processDeletionMonitor(Thread):
	def __init__ (self):
		Thread.__init__(self)
	def run(self):
		pythoncom.CoInitialize ()
		c = wmi.WMI ()
		process_deletion_watcher = c.watch_for (
		  notification_type="Deletion",
		  wmi_class="Win32_Process",
		  delay_secs=1
		)
		while 1:
			p1 = process_deletion_watcher  ()
			logger.info("Process %s Deleted" % p1.Name)
			try:
				del procs[p1.ProcessId]
			except:
				pass
				
			
class printJobMonitor(Thread):
	def __init__ (self):
		Thread.__init__(self)
	def run(self):
		pythoncom.CoInitialize ()
		c = wmi.WMI ()
		print_job_watcher = c.watch_for (
		  notification_type="Creation",
		  wmi_class="Win32_PrintJob",
		  delay_secs=1
		)
		while 1:
			p2 = print_job_watcher  ()
			logger.info("User %s has submitted the document %s to printer %s" % (p2.Owner, p2.Document, p2.Name))
	  
class mediaMonitor(Thread):
	def __init__ (self):
		Thread.__init__(self)
	def run(self):
		pythoncom.CoInitialize ()
		c = wmi.WMI ()
		media_watcher = c.watch_for (
		  notification_type="Creation",
		  wmi_class="Win32_DiskDrive",
		  delay_secs=2,
		  InterfaceType="USB"
		)
		while 1:
			p2 = media_watcher ()
			logger.info("Usb Disk Connected: %s" % (p2.PNPDeviceID))
	  
class sharesMonitor(Thread):
	def __init__ (self):
		Thread.__init__(self)
	def run(self):
		pythoncom.CoInitialize ()
		c = wmi.WMI ()
		share_watcher = c.watch_for (
		  notification_type="Creation",
		  wmi_class="Win32_Share",
		  delay_secs=1
		)
		while 1:
			p2 = share_watcher ()
			logger.info("Shared resource %s mapped to %s" % (p2.Name, p2.Path))

class accountMonitor(Thread):
	def __init__ (self):
		Thread.__init__(self)
	def run(self):
		pythoncom.CoInitialize ()
		c = wmi.WMI ()
		account_watcher = c.watch_for (
		  notification_type="Creation",
		  wmi_class="Win32_UserAccount",
		  delay_secs=2
		)
		while 1:
			p2 = account_watcher ()
			logger.info("User account %s created" % p2.Name)
			
class logonMonitor(Thread):
	def __init__ (self):
		Thread.__init__(self)
	def run(self):
		pythoncom.CoInitialize ()
		c = wmi.WMI ()
		logon_watcher = c.watch_for (
		  notification_type="Creation",
		  wmi_class="Win32_LoggedOnUser",
		  delay_secs=2
		)
		while 1:
			p2 = logon_watcher ()
			logger.info("User %s logged using %s session via %s" % (p2.Antecedent.Caption, logonTypes[p2.Dependent.LogonType], p2.Dependent.AuthenticationPackage))

class shareAccessMonitor(Thread):
	def __init__ (self):
		Thread.__init__(self)
	def run(self):
		pythoncom.CoInitialize ()
		c = wmi.WMI ()
		share_access_watcher = c.watch_for (
		  notification_type="Creation",
		  wmi_class="Win32_ServerConnection",
		  delay_secs=2
		)
		while 1:
			p2 = share_access_watcher ()
			logger.info("User %s access shared resource %s" % (p2.UserName, p2.ShareName))

class firewallMonitor(Thread):
	def __init__ (self):
		Thread.__init__(self)
		self.ports = []
		self.apps = []
		self.status = True
	def run(self):
		time.sleep(3)
		try:
			XPFW = win32com.client.gencache.EnsureDispatch('HNetCfg.FwMgr',0)
			XPFW_Policy = XPFW.LocalPolicy.CurrentProfile
			if XPFW_Policy.FirewallEnabled != self.status:
				self.status = XPFW_Policy.FirewallEnabled
				if XPFW_Policy.FirewallEnabled:
					logger.info("Firewall is enabled")
				else:
					logger.info("Firewall is disabled")
			for port in XPFW_Policy.GloballyOpenPorts:
				if not ports.index(port.Port):
					ports.append(port.Port)
					logger.info("Port %s is open for the Windows Firewall" % port.Port)
			for app in XPFW_Policy.AuthorizedApplications:
				if not apps.index(app.Name):
					apps.append(app.Name)
					logger.info("Application %s allowed for the Windows Firewall" % app.Name)
		except pythoncom.com_error:
			logger.debug("Error accesing Windows Firewall Information")	
		
	
config = ConfigParser.ConfigParser()
config.read('config.cfg')
verbose = config.get('log', 'verbose')
Logger.set_verbose(verbose)

if config.has_option("log", "file"):
	Logger.add_file_handler(config.get('log', 'file'))
#if config.has_option("log", "remoteip"):
#	Logger.add_syslog_handler(config.get('log', 'remoteip'))
	
logger.debug("Starting Application")

#Process Monitor
if config.has_option("process", "enable"):
	if config.get('process', 'enable') == "True":
		logger.debug("Starting Process Monitor")
		regProcess()
		procCreMon = processCreationMonitor()
		procCreMon.start()
		procDelMon = processDeletionMonitor()
		procDelMon.start()

#Printer Monitor
if config.has_option("printer", "enable"):
	if config.get('printer', 'enable') == "True":
		logger.debug("Starting Printer Monitor")
		priMon = printJobMonitor()
		priMon.start()

#Media Monitor
if config.has_option("media", "enable"):
	if config.get('media', 'enable') == "True":
		logger.debug("Starting Media Monitor")
		medMon = mediaMonitor()
		medMon.start()

#File Monitor
filters = []
for key, value in config.items('file'):
  if key != 'enable' and key != 'path':
    filters.append(value)
    
if config.has_option("file", "enable") and len(filters) > 0:
	if config.get('file', 'enable') == "True":
		logger.debug("Starting File Monitor")
                path = config.get('file', 'path')
		fileMonitor = fileMon.fileMon(logger, path, filters)
		fileMonitor.start()
		
#Share Monitor
if config.has_option("shares", "enable"):
	if config.get('shares', 'enable') == "True":
		logger.debug("Starting Shares Monitor")
		shMon = sharesMonitor()
		shMon.start()
		
#Account Monitor
if config.has_option("account", "enable"):
	if config.get('account', 'enable') == "True":
		logger.debug("Starting Account Monitor")
		acMon = accountMonitor()
		acMon.start()
		
#Logon Monitor
if config.has_option("logon", "enable"):
	if config.get('logon', 'enable') == "True":
		logger.debug("Starting Logon Monitor")
		acMon = accountMonitor()
		acMon.start()
		
#Share Access
if config.has_option("share-access", "enable"):
	if config.get('share-access', 'enable') == "True":
		logger.debug("Starting Share Access Monitor")
		acMon = shareAccessMonitor()
		acMon.start()
		
#Firewall Monitor
if config.has_option("firewall", "enable"):
	if config.get('firewall', 'enable') == "True":
		logger.debug("Starting Firewall Monitor")
		fireMon = firewallMonitor()
		fireMon.start()


      


