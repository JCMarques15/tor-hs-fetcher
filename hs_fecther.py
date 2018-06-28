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
import binascii

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
    self.v2_full_descriptor_regex = re.compile("rendezvous-service-descriptor.*?-----END SIGNATURE[-]{0,5}", re.DOTALL)
    self.v3_full_descriptor_regex = re.compile(r"hs-descriptor\s[\d].*?signature\s.*?\s", re.DOTALL)
    self.v3_cert_regex = re.compile("[-]{0,5}BEGIN ED25519 CERT[-]{0,5}\n(.*?)\n[-]{0,5}END ED25519 CERT[-]{0,5}", re.DOTALL)
    self.rendezvous_regex = re.compile(r"rendezvous-service-descriptor\s(.*)")
    self.descriptor_version_regex = re.compile(r"version\s(.*)")
    self.descriptor_pkey_regex = re.compile("permanent-key\n-----BEGIN RSA PUBLIC KEY-----(.*?)-----END RSA PUBLIC KEY-----", re.DOTALL)
    self.secret_id_regex = re.compile(r"secret-id-part\s(.*)")
    self.publication_time_regex = re.compile(r"publication-time\s(.*)")
    self.protocol_versions_regex = re.compile(r"protocol-versions\s(.*)")
    self.introduction_points_encoded_regex = re.compile("introduction-points\n-----BEGIN MESSAGE-----\n(.*?)\n-----END MESSAGE-----", re.DOTALL)
    self.signature_regex = re.compile("signature\n-----BEGIN SIGNATURE-----(.*?)-----END SIGNATURE[-]{0,5}", re.DOTALL)
    self.full_introduction_points_decoded_regex = re.compile("introduction-point.*?-----END RSA PUBLIC KEY-----.*?-----END RSA PUBLIC KEY-----", re.DOTALL)

    # Initialize counters
    self.v2_descriptor_counter = 0
    self.v3_descriptor_counter = 0

  def run(self):
    print ("Starting {} with pid: {}".format(self.name, self.pid))

    # Call dump memory and store the output of the script for processing
    self.script_output = self.dump_memory(self.pid)
    for self.line in self.script_output:
      print(self.line)

    # Reads the contents of the strings file into a variable
    with open("{}/Memory_Dumps/{}H-{}.str".format(sys.path[0], self.extraction_datetime, self.pid), "r") as self.strings_file:
      self.file_contents = self.strings_file.read()

    # Try to extract V3 descriptors out of the strings file
    try:
      # Takes all of the v3 descriptors out of the strings file and extracts the cert for identification purposes
      for self.v3_descriptor in self.v3_full_descriptor_regex.finditer(self.file_contents):
        # Extract the certificate for comparison
        self.v3_cert = self.v3_cert_regex.search(self.v3_descriptor.group(0)).group(1).replace('\n', '')
        
        # Acquire lock to interact with DB
        self.lock.acquire()
        print("{}: Acquired lock!".format(self.name))

        # Check if cert is already in DB, if not call function to add it
        if (self.cursor.execute("SELECT EXISTS(SELECT * FROM v3_descriptors WHERE descriptor_cert='{}')".format(self.v3_cert,)).fetchone()[0] == 0):
          self.db_insert_v3_cert()
          self.v3_descriptor_counter += 1
        else:
          print("[-] V3 cert already in the Database!")
        
        # Commit changed to DB and release the lock
        self.db.commit()
        self.lock.release()
        print("{}: Released lock!\n".format(self.name))
    # If no V3 descriptors are found it prints a message and continues to V2 descriptors extraction
    except TypeError as err:
      print("No V3 descriptors found! Error: {}".format(err.args))

    # Try to extract V2 descriptors out of the strings file
    try:
      # Takes all of the V2 descriptors out of the strings variable and process each one by one
      for self.descriptor in self.v2_full_descriptor_regex.finditer(self.file_contents):
        # try to extract the fields of the descriptor
        try:
          # Extracts each field into his own variable
          self.rendezvous = self.rendezvous_regex.search(self.descriptor.group(0)).group(1)
          self.descriptor_version = self.descriptor_version_regex.search(self.descriptor.group(0)).group(1)
          self.pkey = self.descriptor_pkey_regex.search(self.descriptor.group(0)).group(1).replace('\n', '')
          self.secret_id = self.secret_id_regex.search(self.descriptor.group(0)).group(1)
          self.publication_time = self.publication_time_regex.search(self.descriptor.group(0)).group(1)
          self.protocol_versions = self.protocol_versions_regex.search(self.descriptor.group(0)).group(1)
          try:
            self.introduction_points_encoded = self.introduction_points_encoded_regex.search(self.descriptor.group(0)).group(1).replace('\n', '')
          except AttributeError:
            self.introduction_points_encoded = None
          self.signature = self.signature_regex.search(self.descriptor.group(0)).group(1).replace('\n', '')
          self.onion_link = "{}.onion".format(self.calc_onion_link(self.pkey))
          
          # Extracts each introduction point and adds it to a list
          if (self.introduction_points_encoded is not None):
            self.introduction_points_list = list(self.full_introduction_points_decoded_regex.finditer(self.decode_introduction_points(self.introduction_points_encoded)))
            self.introduction_points_count = len(self.introduction_points_list)
          else:
            self.introduction_points_list = None
            self.introduction_points_count = 0
        # Captures an exception raised when there is an error on the decoding of certain fields
        # It prints a message and continues to the next descriptor without inserting into the database
        except UnicodeDecodeError:
          print("Found descriptor with bad encoding!\n")
          continue
        except binascii.Error as err:
          print("Encoding error:\n{}".format(err.args))
          continue

        # Thread acquires the lock to access the database
        self.lock.acquire()
        print("{}: Acquired lock!".format(self.name))

        # Checks if there is already an entry for the onion link
        if (self.cursor.execute("SELECT EXISTS(SELECT * FROM hidden_services WHERE link='{}')".format(self.onion_link,)).fetchone()[0] == 0):
          # if there isn't then it calls the function to add it
          self.db_insert_link()
          self.v2_descriptor_counter += 1
        else:
          # If there is then retrieves the link_id of the entry for later use
          print("[-] Onion link already in the Database")
          self.onion_link_id = self.cursor.execute("SELECT id FROM hidden_services WHERE link='{}'".format(self.onion_link)).fetchone()[0]
          print("Onion link id is: {}".format(self.onion_link_id))

        # Check if there is already a descriptor entry for the onion link
        if (self.cursor.execute("SELECT EXISTS(SELECT link_id, publication_time FROM descriptors WHERE link_id='{}')".format(self.onion_link_id)).fetchone()[0] == 0):
          # If there isn't then call function to insert descriptor, also calls the function to add it to the snapshot table
          self.db_insert_descriptor()
          self.snapshot_insert_descriptor()
        else:
          # If there is an entry, it checks if the entry publication time is the same as the newly extracted descriptor
          if (self.cursor.execute("SELECT EXISTS(SELECT link_id, publication_time FROM descriptors WHERE link_id='{}' and publication_time='{}')".format(self.onion_link_id, self.publication_time)).fetchone()[0] == 0):
            # If it is not then it calls the function to updates the entry in the database and also calls the function to add it to the snapshot
            self.db_update_descriptor()
            self.snapshot_insert_descriptor()
          else:
            # If it is the same then just prints a message and continues
            print("[-] Descriptor is still the same as the one in the Database!")

        # At the end of each entry it commits the changes to the database file and releases the lock so other threads can access the database
        self.db.commit()
        self.lock.release()
        print("{}: Released lock!\n".format(self.name))

      # Aquire lock at the end and add to the database to a specific table the amount of new links with date of the scan
      self.lock.acquire()
      print("{}: Acquired lock!".format(self.name))
      print("[+] Inserting extraction stats into Database")
      self.cursor.execute("INSERT INTO extraction_stats(v2, v3, extraction_date, pid) VALUES(?,?,?,?)", (self.v2_descriptor_counter, self.v3_descriptor_counter, "{}H".format(self.extraction_datetime), self.pid))
      self.db.commit()
      self.lock.release()
      print("{}: Released lock!\n".format(self.name))
    # If nothing gets extracted it captures the exception 
    # raised from trying to iterate an empty object and prints a message
    except TypeError as err:
      print("No V2 descriptors found! Error: {}".format(err.args))
    except sqlite3.OperationalError as err:
          print("Sqlite error:\n{}".format(err.args))
          sys.exit(1)
    print ("Exiting {}".format(self.name))

  # Function to insert new links into the database
  def db_insert_link(self):
    print("[+] Inserting Onion link into the Database")
    self.cursor.execute("INSERT INTO hidden_services(link, reachable, classification) VALUES(?,?,?)", (self.onion_link, "Unknown", "None"))
    self.onion_link_id = self.cursor.lastrowid

  # Function to update the fields of an existing entry in the database
  def db_update_link(self):
    print("[+]  Updating Onion link info in the Database")
    # TODO: Add update code
    # self.cursor.execute("UPDATE hidden_services SET reachable='?' classification='?' WHERE link='?'", (self.onion_link,))

  # Function to insert new descriptors
  def db_insert_descriptor(self):
    print("[+] Inserting the descriptor into the Database")
    self.cursor.execute("INSERT INTO descriptors(link_id, rendezvous_service_descriptor, format_version, permanent_key, secret_id_part, publication_time, protocol_versions, introduction_points_count, descriptor_signature) VALUES(:link_id, :rendezvous, :format_version, :permanent_key, :secret_id, :publication_time, :protocol_versions, :introduction_points_count, :descriptor_signature)", {
      "link_id":self.onion_link_id, 
      "rendezvous":self.rendezvous,
      "format_version":self.descriptor_version, 
      "permanent_key":self.pkey, 
      "secret_id":self.secret_id, 
      "publication_time":self.publication_time, 
      "protocol_versions":self.protocol_versions,
      "introduction_points_count":self.introduction_points_count, 
      "descriptor_signature":self.signature})

    if (self.introduction_points_list is not None):
      print("[+] Inserting the Introduction Points into the Database")
      self.ip_counter = 0
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

  # Function to update the entry in the database with the newly published descriptor
  def db_update_descriptor(self):
    print("[+] Updating the descriptor entry in the Database")
    self.cursor.execute("UPDATE descriptors SET rendezvous_service_descriptor='{}', format_version='{}', permanent_key='{}', secret_id_part='{}', publication_time='{}', protocol_versions='{}', introduction_points_count='{}', descriptor_signature='{}' WHERE link_id='{}'".format(self.rendezvous, self.descriptor_version, self.pkey, self.secret_id, self.publication_time, self.protocol_versions, self.introduction_points_count, self.signature, self.onion_link_id,))

    print("[+] Updating the descriptor introduction points in the Database")
    self.cursor.execute("DELETE FROM descriptors_introduction_points WHERE link_id='{}'".format(self.onion_link_id,))
    if (self.introduction_points_list is not None):
      self.ip_counter = 0
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
      
  # Function to insert the descriptor into a snapshot table for archiving purposes 
  def snapshot_insert_descriptor(self):
    print("[+] Inserting the descriptor snapshot into the Database")
    self.cursor.execute("INSERT INTO descriptors_snapshot(link_id, rendezvous_service_descriptor, format_version, permanent_key, secret_id_part, publication_time, protocol_versions, introduction_points, descriptor_signature) VALUES(:link_id, :rendezvous, :format_version, :permanent_key, :secret_id, :publication_time, :protocol_versions, :introduction_points, :descriptor_signature)", {
      "link_id":self.onion_link_id, 
      "rendezvous":self.rendezvous,
      "format_version":self.descriptor_version, 
      "permanent_key":self.pkey, 
      "secret_id":self.secret_id, 
      "publication_time":self.publication_time, 
      "protocol_versions":self.protocol_versions,
      "introduction_points":self.introduction_points_encoded, 
      "descriptor_signature":self.signature})

  def db_insert_v3_cert(self):
    print("[+] Inserting v3 cert into the Database")
    self.cursor.execute("INSERT INTO v3_descriptors(descriptor_cert) VALUES(?)", (self.v3_cert,))

  # Function to call the shell script to make the hourly memory dump of the tor processes
  # TODO: Convert from the shell scrip to native python code
  def dump_memory(self, pid):
    self.process_manager = subprocess.Popen(["{}/process_dumper.sh".format(sys.path[0]), pid], stdout=subprocess.PIPE, universal_newlines=True)
    self.output, self._err = self.process_manager.communicate()
    return self.output.splitlines()

  # Function to call the shell script that calculates the onion link from the public key
  # TODO: Convert from the shell scrip to native python code
  def calc_onion_link(self, pkey):
    print("Decoding publick key and extracting the onion link!")
    self.process_manager = subprocess.Popen(["{}/onion-link-calc.sh".format(sys.path[0]), pkey], stdout=subprocess.PIPE, universal_newlines=True)
    self.output, self._err = self.process_manager.communicate()
    print("Decoded link: {}.onion".format(self.output.splitlines()[0]))
    return self.output.splitlines()[0]

  # Function that decodes the instruction pointers message field of the descriptor
  def decode_introduction_points(self, encoded_introduction_points):
    print("Decoding instruction pointers message" )
    self.output = base64.decodestring(encoded_introduction_points.encode('utf-8'))
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