#!/bin/sh

while true; do
  echo "Choose one of the following options to print the corresponding table:"
  read -p "\tHidden Services - 1\n
           \tV2-Descriptors - 2\n
           \tV2-Introduction Points - 3\n
           \tV2-Descriptor Snapshots - 4\n
           \tV3-Descriptor Certs - 5\n
           \tExtraction Stats - 6\n\n" query
  case $query in
    [1]* ) *;;
    [2]* ) *;;
    [3]* ) *;;
    [4]* ) sqlite3 hidden_services.db "select * from descriptors_snapshot" | awk -F"|" '{for(c=0;c<82;c++) printf "-"; print "\nID\tLink_ID\t\tDescriptor_Fingerprint\t\t\tDescriptor_Version"; print $1"\t"$2"\t\t"$3"\t"$4; print "\nPublic-Key\n"$5; print "\nSecret-ID\t\t\t\tPublication_time\tProtocol_Version"; print $6"\t"$7"\t"$8; print "\nIntroduction_points\n"$9; print "\nSignature\n"$10;}' | less;;
    [5]* ) sqlite3 hidden_services.db "select * from v3_descriptors" | awk -F"|" 'BEGIN{print "ID\tCERT"} {print $1"\t"$2}' | less;;
    [6]* ) sqlite3 hidden_services.db "select * from extraction_stats;" | awk -F"|" 'BEGIN{print "V3\tV2\tDATE\t\tProcess"} {print $1"\t"$2"\t"$3"\t"$4}' | less;;