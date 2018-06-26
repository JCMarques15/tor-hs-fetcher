#!/usr/bin/env python3

import subprocess
import subprocess
import sys 
import threading
import sqlite3
import re
import datetime
from pathlib import Path
import base64

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
    
    # Initialize variable with formated date for later directory naming
    self.extraction_datetime = datetime.datetime.today().strftime('%Y-%m-%d-%H')

    # Initialize regex processing rules
    self.full_descriptor_regex = re.compile("rendezvous-service-descriptor.*?-----END SIGNATURE-----", re.DOTALL)
    self.rendezvous_regex = re.compile(r"rendezvous-service-descriptor\s(.*)")
    self.descriptor_version_regex = re.compile(r"version\s(.*)")
    self.descriptor_pkey_regex = re.compile("permanent-key\n-----BEGIN RSA PUBLIC KEY-----(.*?)-----END RSA PUBLIC KEY-----", re.DOTALL)
    self.secret_id_regex = re.compile(r"secret-id-part\s(.*)")
    self.publication_time_regex = re.compile(r"publication-time\s(.*)")
    self.protocol_versions_regex = re.compile(r"protocol-versions\s(.*)")
    self.introduction_points_encoded_regex = re.compile("introduction-points\n-----BEGIN MESSAGE-----\n(.*?)\n-----END MESSAGE-----", re.DOTALL)
    self.signature_regex = re.compile("signature\n-----BEGIN SIGNATURE-----(.*?)-----END SIGNATURE-----", re.DOTALL)

    # Initialize regex to process decoded introduction points
    self.full_introduction_points_decoded_regex = re.compile("introduction-point.*?-----END RSA PUBLIC KEY-----.*?-----END RSA PUBLIC KEY-----", re.DOTALL)


  def run(self):
    print ("Starting {} with pid: {}".format(self.name, self.pid))

    # Call dump memory and store the output of the script for processing
    self.script_output = self.dump_memory(self.pid)
    for self.line in self.script_output:
      print(self.line)

    # Reads the contents of the strings file into a variable
    with open("{}/Memory_Dumps/{}H-{}.str".format(sys.path[0], self.extraction_datetime, self.pid), "r") as self.strings_file:
      self.file_contents = self.strings_file.read()

    try:
      # Takes all of the descriptors out of the strings variable and process each one by one
      for self.descriptor in self.full_descriptor_regex.finditer(self.file_contents):
        # try to extract the field
        try:
          # Extracts each field into his own variable
          self.rendezvous = self.rendezvous_regex.search(self.descriptor.group(0)).group(1)
          self.descriptor_version = self.descriptor_version_regex.search(self.descriptor.group(0)).group(1)
          self.pkey = self.descriptor_pkey_regex.search(self.descriptor.group(0)).group(1)
          self.secret_id = self.secret_id_regex.search(self.descriptor.group(0)).group(1)
          self.publication_time = self.publication_time_regex.search(self.descriptor.group(0)).group(1)
          self.protocol_versions = self.protocol_versions_regex.search(self.descriptor.group(0)).group(1)
          self.introduction_points_encoded = self.introduction_points_encoded_regex.search(self.descriptor.group(0)).group(1).strip()
          self.signature = self.signature_regex.search(self.descriptor.group(0)).group(1)
          self.onion_link = "{}.onion".format(self.calc_onion_link(self.pkey))
          # Extracts each introduction point and adds it to a list
          self.introduction_points_list = self.full_introduction_points_decoded_regex.finditer(self.decode_introduction_points(self.introduction_points_encoded))
        except UnicodeDecodeError:
          print("Found descriptor with bad encoding!")
          continue

        self.lock.acquire()
        print("{}: Acquired lock!".format(self.name))
        if (self.cursor.execute("SELECT EXISTS(SELECT * FROM hidden_services WHERE link='{}')".format(self.onion_link,)).fetchone()[0] == 0):
          print("[+]Inserting Onion link into the Database")
          self.cursor.execute("INSERT INTO hidden_services(link) VALUES(?)", (self.onion_link,))
          self.onion_link_id = self.cursor.lastrowid
        else:
          print("[-]Onion link already in the Database")
          self.onion_link_id = self.cursor.execute("SELECT id FROM hidden_services WHERE link='{}'".format(self.onion_link)).fetchone()[0]
          print("Onion link id is: {}".format(self.onion_link_id))

        if (self.cursor.execute("SELECT EXISTS(SELECT link_id, publication_time FROM descriptors WHERE link_id='{}' and publication_time='{}')".format(self.onion_link_id, self.publication_time)).fetchone()[0] == 0):
          print("[+]Inserting the descriptor field into the Database")
          self.cursor.execute("INSERT INTO descriptors(link_id, rendezvous_service_descriptor, format_version, permanent_key, secret_id_part, publication_time, protocol_versions, descriptor_signature) VALUES(:link_id, :rendezvous, :format_version, :permanent_key, :secret_id, :publication_time, :protocol_versions, :descriptor_signature)", {
            "link_id":self.onion_link_id, 
            "rendezvous":self.rendezvous,
            "format_version":self.descriptor_version, 
            "permanent_key":self.pkey, 
            "secret_id":self.secret_id, 
            "publication_time":self.publication_time, 
            "protocol_versions":self.protocol_versions, 
            "descriptor_signature":self.signature})

          self.ip_counter = 0
          print("[+]Inserting the Introduction Points into the Database")
          for self.entry in self.introduction_points_list:
            self.ip_counter+=1
            self.fields = re.match(r"introduction-point\s(.*?)\sip-address\s(.*?)\sonion-port\s(.*?)\sonion-key\s-----BEGIN RSA PUBLIC KEY-----\s(.*?)\s-----END RSA PUBLIC KEY-----\sservice-key\s-----BEGIN RSA PUBLIC KEY-----\s(.*?)\s-----END RSA PUBLIC KEY-----", self.entry.group(0), re.DOTALL)
            self.cursor.execute("INSERT INTO descriptors_introduction_points(id, link_id, introduction_point, ip_address, onion_port, onion_key, service_key) VALUES(:id, :link_id, :introduction_point, :ip, :port, :onion_key, :service_key)", {
              "id":self.ip_counter,
              "link_id":self.onion_link_id,
              "introduction_point":self.fields.group(1),
              "ip":self.fields.group(2),
              "port":self.fields.group(3),
              "onion_key":self.fields.group(4),
              "service_key":self.fields.group(5)})
        else:
          print("[-]Descriptor is still the same as the one in the Database!")

        self.db.commit()
        self.lock.release()
        print("{}: Released lock!\n".format(self.name))
    except TypeError as err:
      print("No descriptors found! Error: {}".format(err.args))
    print ("Exiting {}".format(self.name))

  def dump_memory(self, pid):
    self.process_manager = subprocess.Popen(["{}/process_dumper.sh".format(sys.path[0]), pid], stdout=subprocess.PIPE, universal_newlines=True)
    self.output, self._err = self.process_manager.communicate()
    return self.output.splitlines()

  def calc_onion_link(self, pkey):
    print("Decoding publick key and extracting the onion link!")
    self.process_manager = subprocess.Popen(["{}/onion-link-calc.sh".format(sys.path[0]), pkey], stdout=subprocess.PIPE, universal_newlines=True)
    self.output, self._err = self.process_manager.communicate()
    print("Decoded link: {}.onion".format(self.output.splitlines()[0]))
    return self.output.splitlines()[0]

  def decode_introduction_points(self, encoded_introduction_points):
    print("Decoding instruction pointers message" )
    self.output = base64.decodestring(encoded_introduction_points.encode('utf-8').strip())
    print("Decoded the instruction pointers!")
    return self.output.decode('utf-8')
    


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

  if Path("{}/hidden_services.db".format(sys.path[0])).is_file():
    print("Database exists, opening it up...")
    db = sqlite3.connect("{}/hidden_services.db".format(sys.path[0]), check_same_thread=False)
  else:
    print("Database doesn't exist, creating it...")
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