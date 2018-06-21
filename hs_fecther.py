#!/usr/bin/env python3

import subprocess
import sys
import threading
import sqlite3

class myThread (threading.Thread):
  def __init__(self, threadID, name, pid):
    threading.Thread.__init__(self)
    self.threadID = threadID
    self.name = name
    self.pid = pid

  def run(self):
    print ("Starting {} with pid: {}".format(self.name, self.pid))

    # Call dump memory and store the output of the script for processing
    script_output = self.dump_memory(self.pid)
    for line in script_output:
      print(line)
      
      
    # TODO: add calls to the scripts and process data!!
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