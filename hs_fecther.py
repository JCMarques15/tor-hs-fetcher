#!/usr/bin/env python3

import subprocess
import subprocess
import sys 
import threading
import sqlite3
import re
import datetime
from pathlib import Path

class myThread (threading.Thread):
  def __init__(self, threadID, name, pid, db, lock):
    threading.Thread.__init__(self)
    # Initialize variables passed on object creation
    self.threadID = threadID
    self.name = name
    self.pid = pid
    self.db = db
    self.cursor = db.cursor()
    self.lock = lock
    
    # Initalize variable with formated date for later directory naming
    self.extraction_datetime = datetime.datetime.today().strftime('%Y-%m-%d-%H')

    # Initialize regex processing rules
    self.full_descriptor_regex = re.compile("rendezvous-service-descriptor.*?-----END SIGNATURE-----", re.DOTALL)
    self.rendezvous_regex = re.compile("rendezvous-service-descriptor\s(.*)")
    self.descriptor_version_regex = re.compile("version\s(.*)")
    self.descriptor_pkey_regex = re.compile("permanent-key\n-----BEGIN RSA PUBLIC KEY-----(.*?)-----END RSA PUBLIC KEY-----", re.DOTALL)
    self.secret_id_regex = re.compile("secret-id-part\s(.*)")
    self.publication_time_regex = re.compile("publication-time\s(.*)")
    self.protocol_versions_regex = re.compile("protocol-versions\s(.*)")
    self.introduction_points_encoded_regex = re.compile("introduction-points\n-----BEGIN MESSAGE-----(.*?)-----END MESSAGE-----", re.DOTALL)
    self.signature_regex = re.compile("signature\n-----BEGIN SIGNATURE-----(.*?)-----END SIGNATURE-----", re.DOTALL)

    # Initialize regez to process decoded introduction points
    self.full_introduction_points_decoded_regex = re.compile("introduction-point.*?-----END RSA PUBLIC KEY-----.*?-----END RSA PUBLIC KEY", re.DOTALL)


  def run(self):
    print ("Starting {} with pid: {}".format(self.name, self.pid))

    # Call dump memory and store the output of the script for processing
    self.script_output = self.dump_memory(self.pid)
    for self.line in self.script_output:
      print(self.line)

    # Reads the contents of the strings file into a variable
    with open("{}/Memory_Dumps/{}H-{}.str".format(sys.path[0], self.extraction_datetime, self.pid), "r") as self.strings_file:
      self.file_contents = self.strings_file.read()
    
    # Takes all of the descriptors out of the strings variable and process each one by one
    for self.descriptor in self.full_descriptor_regex.match(self.file_contents):
      # Extracts each field into his own variable
      self.rendezvous = self.rendezvous_regex.match(self.descriptor).group(1)
      self.descriptor_version = self.descriptor_version_regex.match(self.descriptor).group(1)
      self.pkey = self.descriptor_pkey_regex.match(self.descriptor).group(1)
      self.secret_id = self.secret_id_regex.match(self.descriptor).group(1)
      self.publication_time = self.publication_time_regex.match(self.descriptor).group(1)
      self.protocol_versions = self.protocol_versions_regex.match(self.descriptor).group(1)
      self.introduction_points_encoded = self.introduction_points_encoded_regex.match(self.descriptor).group(1)
      self.signature = self.signature_regex.match(self.descriptor).group(1)
      self.onion_link = "{}.onion".format(self.calc_onion_link(self.pkey))

      # Extracts each introduction point and adds it to a list
      self.introduction_points_list = self.full_introduction_points_decoded_regex.match(self.decode_introduction_points(self.introduction_points_encoded))

      with self.lock.acquire():
        print("{}: Aquired lock".format(self.name))
        self.cursor.execute("INSERT INTO hidden_services(link) VALUES(?)", (self.onion_link,))
        self.onion_link_id = self.cursor.execute("SELECT id FROM hidden_services WHERE link=?", (self.onion_link,))
        self.cursor.execute("INSERT INTO descriptors(link_id, rendezvous_service_descriptor, descriptor_id, format_version, permanent_key, secret_id_part, publication_time, protocol_versions, descriptor_signature) VALUES(:link_id, :rendezvous, :descriptor_id, :format_version, :permanent_key, :secret_id, :publication_time, :protocol_versions, :descriptor_signature)", {
          "link_id":self.onion_link_id, 
          "rendezvous":self.rendezvous,
          "format_version":self.descriptor_version, 
          "permanent_key":self.pkey, 
          "secret_id":self.secret_id, 
          "publication_time":self.publication_time, 
          "protocol_versions":self.protocol_versions, 
          "descriptor_signature":self.signature})
        self.ip_counter = 0
        for self.entry in self.introduction_points_list:
          self.ip_counter+=1
          self.fields = re.match("introduction-point\s(.*?)\sip-address\s(.*?)\sonion-port\s(.*?)\sonion-key\s-----BEGIN RSA PUBLIC KEY-----\s(.*?)\s-----END RSA PUBLIC KEY-----\sservice-key\s-----BEGIN RSA PUBLIC KEY-----\s(.*?)\s-----END RSA PUBLIC KEY-----", self.entry, re.DOTALL).group()
          self.cursor.execute("INSERT INTO descriptors_introduction_points(id, link_id, introduction_point, ip_address, onion_port, onion_key, service_key) VALUES(:id, :link_id, :introduction_point, :ip, :port, :onion_key, :service_key)", {
            "id":self.ip_counter,
            "link_id":self.onion_link_id,
            "introduction_point":self.fields[0],
            "ip":self.fields[1],
            "port":self.fields[2],
            "onion_key":self.fields[3],
            "service_key":self.fields[4]})
        self.db.commit()
      #self.lock.release()
      print("{}: Released lock".format(self.name))

    print ("Exiting {}".format(self.name))

  def dump_memory(self, pid):
    self.process_manager = subprocess.Popen(["{}/process_dumper.sh".format(sys.path[0]), pid], stdout=subprocess.PIPE, universal_newlines=True)
    self.output, self._err = self.process_manager.communicate()
    return self.output.splitlines()

  def calc_onion_link(self, pkey):
    self.process_manager = subprocess.Popen(["{}/onion-link-calc.sh".format(sys.path[0]), pkey], stdout=subprocess.PIPE, universal_newlines=True)
    self.output, self._err = self.process_manager.communicate()
    return self.output.splitlines()[0]

  def decode_introduction_points(self, encoded_introduction_points):
    self.process_manager_echo = subprocess.Popen(["echo", encoded_introduction_points], stdout=subprocess.PIPE)
    self.process_manager_base64 = subprocess.Popen(["base64", "-d"], stdin=self.process_manager_echo.stdout, stdout=subprocess.PIPE, universal_newlines=True)
    self.output, self._err = self.process_manager_base64.communicate()
    return self.output


def extract_pid():
  process_manager = subprocess.Popen(['pgrep', '^tor'], stdout=subprocess.PIPE, universal_newlines=True)
  output, _err = process_manager.communicate()
  return output.splitlines()


def main():
  # Variable declaration
  tor_pid = extract_pid()
  thread_counter=0
  thread_list=[]
  lock = threading.Lock()

  if Path("{}/hidden_serbices.db".format(sys.path[0])).is_file():
    print("Database exists, opening it up...")
    db = sqlite3.connect("{}/hidden_services.db".format(sys.path[0]), check_same_thread=False)
  else:
    print("Database doesnt exist, creating it...")
    db = sqlite3.connect("{}/hidden_services.db".format(sys.path[0]), check_same_thread=False)
    cursor = db.cursor()
    with open("{}/sqlite_database_create.sql".format(sys.path[0])) as create_sql:
      cursor.executescript(create_sql.read())

  # Start the threads
  for pid in tor_pid:
    thread_list.append(myThread(thread_counter+1, "Thread-{}".format(thread_counter+1), pid, db, lock))
    thread_counter += 1

  for relay_thread in thread_list:
    relay_thread.start()
    relay_thread.join()

  db.close()
  print("Exiting main thread!")

if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    print("\rCtrl-C captured, Exiting!")
    sys.exit(1)