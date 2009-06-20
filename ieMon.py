import sys
import os
import struct
import time

from pydbg import *
from pydbg.defines import *
from ctypes import *
import utils
import pythoncom 
import win32com.client
from Logger import Logger
from threading import Thread


def incremental_read (dbg, addr, length):
    data = ""
    while length:
        try:
            data += dbg.read_process_memory(addr, 1)
        except:
            break

        addr   += 1
        length -= 1

    return data
        

def get_handle(dbg, id):
    duped = HANDLE()
    if not kernel32.DuplicateHandle(dbg.h_process, id, kernel32.GetCurrentProcess(), byref(duped), 0, False, DUPLICATE_SAME_ACCESS):
        
        return False
    
    return duped

def close_handle(dbg, id):
    if not kernel32.CloseHandle(handle):
        return False
    
    for hi in xrange(0, len(dbg.handles)):
        if dbg.handles[hi]["id"] == id:
            dbg.handles.remove(hi)
            
            return True

    print "[!] Couldnt find handle id 0x%x" % id
    
    return False


class ieMon(Thread):
	def __init__ (self, logger, pid, ieRules):
		Thread.__init__(self)
		self.logger = logger
		self.pid = pid
		self.ieRules = ieRules
		self.filters = ["ole32.dll"]
		self.library = [{"id":1,
			     "dll":"ole32",
			     "func":"StringFromGUID2",
			     "handler":self.handler_instance,
			     "args":3,
			     "hit":0,
			     "on":True
			   }]
	def run(self):
		self.handles = []
		self.buffers = []
		self.dbg = ""
		self.loop_limit = 10
		self.dbg = pydbg()
		self.dbg.filters = self.filters
		self.dbg.library = self.library
		self.dbg.handles = self.handles
		self.dbg.buffers = self.buffers
		self.dbg.hooks = ""
		#self.dbg.procname = self.procname
		self.dbg.loop_limit = self.loop_limit
		self.dbg.set_callback(EXCEPTION_BREAKPOINT, self.handler_breakpoint)
		try:
			self.dbg.attach(self.pid)
		except:
			#logger
			self.logger.info("Couldnt load/attach to pid")
			sys.exit(-1)
		self.logger.debug("ieMon: Attached to pid %d" % self.pid) 
		self.dbg.debug_event_loop()		

	def handler_breakpoint(self, dbg):
	    if dbg.first_breakpoint:
		if not self.set_library_hooks(dbg):
		    self.logger.debug("ieMon: Couldnt set breakpoints")
		    sys.exit(-1)
	    
	    return DBG_CONTINUE
	    
	def set_library_hooks(self, dbg):
	    dbg.hooks = utils.hook_container()
	    for lib in dbg.library:
		if not lib["on"]:
		    continue
		
		address = dbg.func_resolve(lib["dll"], lib["func"])
		self.logger.debug("ieMon: Setting hook @ 0x%08x %s!%s" % (address, lib["dll"], lib["func"]))
		try:
		    dbg.hooks.add(dbg, address, lib["args"], None, lib["handler"])
		except:
		    self.logger.debug("ieMon: Problem setting hook @ 0x%08x %s!%s" % (address, lib["dll"], lib["func"]))
		    
		    return False
	    
	    return True
	    
	def handler_instance(self, dbg, args, ret):
	    #print "CALLED StringFromGUID2"	
	    try:
		clsid = dbg.get_unicode_string(incremental_read(dbg, args[1], 255))
	    except:
		self.logger.debug("Cannot determine clsid")    
		pass
	    self.checkCLSID(clsid)
	    #print "******************************************" + filename	
	    #progIdFromClsid(filename)
	    #print "[*] LoadLibraryA [0x%x] return [0x%08x]"% (filename, ret)
	    
	    return DBG_CONTINUE
	    
	def checkCLSID(self, clsid):
		for r in self.ieRules:
			if r[0] == clsid:
				self.logger.info("ieMon: Called control %s with CLSID %s" % (r[1], r[0]))	
		#self.logger.debug("Called")
	
#We have to call detach
