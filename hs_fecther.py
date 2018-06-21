#!/usr/bin/env python3

import subprocess
import sys
import threading
import sqlite3
import re
import datetime

class myThread (threading.Thread):
  def __init__(self, threadID, name, pid):
    threading.Thread.__init__(self)
    self.threadID = threadID
    self.name = name
    self.pid = pid
    self.extraction_datetime = datetime.datetime.today().strftime('%Y-%m-%d-%H')
    self.file_contents = ""
    self.descriptor_regex = re.compile("rendezvous-service-descriptor.*?-----END SIGNATURE-----", re.DOTALL)
    self.descriptor_pkey_regex = re.compile("-----BEGIN RSA PUBLIC KEY-----(.*?)-----END RSA PUBLIC KEY-----", re.DOTALL)
    self.onion_link = ""

  def run(self):
    print ("Starting {} with pid: {}".format(self.name, self.pid))

    # Call dump memory and store the output of the script for processing
    self.script_output = self.dump_memory(self.pid)
    for self.line in self.script_output:
      print(self.line)

    with open("{}/Memory_Dumps/{}H-{}".format(sys.path[0], self.extraction_datetime, self.pid), "r") as self.strings_file:
      self.file_contents = self.strings_file.read()
    
    for self.descriptor in self.descriptor_regex.match(self.file_contents):
      self.onion_link = "{}.onion".format(self.calc_onion_link(self.descriptor_pkey_regex.match(self.descriptor).group(1)))
       


    print ("Exiting {}".format(self.name))

  def dump_memory(self, pid):
    self.process_manager = subprocess.Popen(["{}/process_dumper.sh".format(sys.path[0]), pid], stdout=subprocess.PIPE, universal_newlines=True)
    self.output, self._err = self.process_manager.communicate()
    return self.output.splitlines()

  def calc_onion_link(self, pkey):
    self.process_manager = subprocess.Popen(["{}/onion-link-calc.sh".format(sys.path[0]), pkey], stdout=subprocess.PIPE, universal_newlines=True)
    self.output, self._err = self.process_manager.communicate()
    return self.output.splitlines()[0]


def extract_pid():
  process_manager = subprocess.Popen(['pgrep', '^tor'], stdout=subprocess.PIPE, universal_newlines=True)
  output, _err = process_manager.communicate()
  return output.splitlines()


def main():
  # Variable declaration
  tor_pid = extract_pid()
  thread_counter=0
  thread_list=[]
  
  db = sqlite3.connect("{}/hidden_services.db".format(sys.path[0]), check_same_thread=False)


  # Start the threads
  for pid in tor_pid:
    thread_list.append(myThread(thread_counter+1, "Thread-{}".format(thread_counter+1), pid))
    thread_counter += 1

  for relay_thread in thread_list:
    relay_thread.start()
    relay_thread.join()

  print("Exiting main thread!")

if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    print("\rCtrl-C captured, Exiting!")
    sys.exit(1)