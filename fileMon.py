import os
import win32file
import win32con
import re
from Logger import Logger
from threading import Thread

class fileMon(Thread):
	def __init__ (self, logger, path, filters):
		Thread.__init__(self)
		self.logger = logger
                self.path = path
                self.filters = filters
                self.exprs = []
                for f in self.filters:
                  self.exprs.append(re.compile(f))
                
                
	def run(self):
		ACTIONS = {
		  1 : "Created",
		  2 : "Deleted",
		  3 : "Updated",
		  4 : "Renamed from something",
		  5 : "Renamed to something"
		}
		FILE_LIST_DIRECTORY = 0x0001

		path_to_watch = self.path
		hDir = win32file.CreateFile (
		  path_to_watch,
		  FILE_LIST_DIRECTORY,
		  win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
		  None,
		  win32con.OPEN_EXISTING,
		  win32con.FILE_FLAG_BACKUP_SEMANTICS,
		  None
		)
		while 1:
		  results = win32file.ReadDirectoryChangesW (
		    hDir,
		    1024,
		    True,
		    win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
		     win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
		     win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
		     win32con.FILE_NOTIFY_CHANGE_SIZE |
		     win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
		     win32con.FILE_NOTIFY_CHANGE_SECURITY,
		    None,
		    None
		  )
		  for action, file in results:
		    full_filename = os.path.join (path_to_watch, file)
                    for exp in self.exprs:
                      m = exp.match(file)
                      if m:
                          self.logger.info("File %s %s" % (file, ACTIONS.get (action, "Unknown")))

