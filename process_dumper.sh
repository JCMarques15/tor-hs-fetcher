#!/usr/bin/env bash

# Check if the script was run by root
# If not then executes it again with sudo
if [ "$EUID" -ne 0 ]; then 
  sudo "$0" "$1"
  exit 0
fi

# Variable declaration
DATE_TIME="$(date +%Y-%m-%d-%HH)"
BASE_DIRECTORY="$(cd $(dirname $0) && pwd)"
DUMPS_DIRECTORY="$BASE_DIRECTORY/Memory_Dumps"
PROCESS_DUMP_DIRECTORY="$DUMPS_DIRECTORY/$DATE_TIME-$1"

# Check if memory dumps directory exists
# if not it creates it
if [ ! -d "$DUMPS_DIRECTORY" ]; then
{
  echo "Creating dumps directory...";
  mkdir "$DUMPS_DIRECTORY";
} 2>&1 | tee -a "$BASE_DIRECTORY/process_dumper.log"
fi

# Check if the hour dump has already been taken
# if not it creates the directory and takes the dump
if [ ! -d "$PROCESS_DUMP_DIRECTORY" ]; then
  if [ ! -f "$PROCESS_DUMP_DIRECTORY.tar.gz" ]; then
    {
    echo "Creating hour dump directory...";
    mkdir "$PROCESS_DUMP_DIRECTORY";
    echo "Starting process...";
    START_TIME="$(date +%s)";
    grep rw-p /proc/"$1"/maps | grep -v "lib" | sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' | while read start stop; do gdb --batch --pid "$1" -ex "dump memory $PROCESS_DUMP_DIRECTORY/$start-$stop.dump 0x$start 0x$stop" &> /dev/null; done;
    END_TIME="$(date +%s)";
    echo "Finished memory dump, run for: $(($END_TIME - $START_TIME)) seconds";
    START_TIME="$(date +%s)";
    strings "$PROCESS_DUMP_DIRECTORY"/*.dump > "$PROCESS_DUMP_DIRECTORY.str"
    END_TIME="$(date +%s)";
    echo "Finished strings dump, run for: $(($END_TIME - $START_TIME)) seconds";    
    START_TIME="$(date +%s)";
    tar --directory "$DUMPS_DIRECTORY" --remove-files -zcf "$DUMPS_DIRECTORY/$DATE_TIME-$1.tar.gz" "$DATE_TIME-$1"
    END_TIME="$(date +%s)";
    echo "Finished archiving dump, run for: $(($END_TIME - $START_TIME)) seconds";
    } 2>&1 | tee -a "$BASE_DIRECTORY/process_dumper.log"
    echo "################################################################" >> "$BASE_DIRECTORY/process_dumper.log"
    chown -R jmarques:jmarques "$DUMPS_DIRECTORY" "$BASE_DIRECTORY/process_dumper.log"
    exit 0
  else
    echo "Dump already exists" | tee -a "$BASE_DIRECTORY/process_dumper.log"
    echo "################################################################" >> "$BASE_DIRECTORY/process_dumper.log"
    exit 1
  fi
else
  if [ ! -f "$PROCESS_DUMP_DIRECTORY.tar.gz" ]; then
    echo "Dump has already been taken but not archived" | tee -a "$BASE_DIRECTORY/process_dumper.log"
    if [ ! -f "$PROCESS_DUMP_DIRECTORY.str" ]; then
      echo "Running strings on the dumps..." | tee -a "$BASE_DIRECTORY/process_dumper.log"
      START_TIME="$(date +%s)";
      strings "$PROCESS_DUMP_DIRECTORY/*.dump" > "$PROCESS_DUMP_DIRECTORY.str"
      END_TIME="$(date +%s)";
      echo "Finished strings dump, run for: $(($END_TIME - $START_TIME)) seconds";
    fi
    echo "Archiving now!" | tee -a "$BASE_DIRECTORY/process_dumper.log"
    START_TIME="$(date +%s)";
    tar --directory "$DUMPS_DIRECTORY" --remove-files -zcf "$DUMPS_DIRECTORY/$DATE_TIME-$1.tar.gz" "$DATE_TIME-$1"
    END_TIME="$(date +%s)";
    echo "Finished archiving dump, run for: $(($END_TIME - $START_TIME)) seconds";
    echo "################################################################" >> "$BASE_DIRECTORY/process_dumper.log"
    exit 0
  else
  echo "Dumps already archived" | tee -a "$BASE_DIRECTORY/process_dumper.log"
  echo "Removing folder!" | tee -a "$BASE_DIRECTORY/process_dumper.log"
  rm -rf "$PROCESS_DUMP_DIRECTORY"
  echo "################################################################" >> "$BASE_DIRECTORY/process_dumper.log"
  exit 1
  fi
fi