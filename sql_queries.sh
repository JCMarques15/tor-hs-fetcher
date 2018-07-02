#!/bin/sh

while true; do
  echo "Choose one of the following options to print the corresponding table:"
  read -p "Hidden Services(1) V2-Descriptors(2) V2-Introduction Points(3) V2-Descriptor Snapshots(4) V3-Descriptor Certs(5) Extraction Stats(6) Quit(Q/q)
  Choice? " query
  
  case $query in
    [1]* ) sqlite3 Database/hidden_services.db "select * from hidden_services" | awk -F"|" '{for(c=0;c<70;c++) printf "-"; print "\nID\tLink\t\t\t\tReachable\tClassification"; print $1"\t"$2"\t\t"$3"\t\t"$4}' | less; clear;;
    [2]* ) sqlite3 Database/hidden_services.db "select * from descriptors" | awk -F"|" '{for(c=0;c<101;c++) printf "-"; print "\nLink_ID\t\tDescriptor_Fingerprint\t\t\tDescriptor_Version"; print $1"\t\t"$2"\t"$3; print "\nPublic-Key\n"$4; print "\nSecret-ID\t\t\t\tPublication_time\tProtocol_Version\tNumber_of_IPs"; print $5"\t"$6"\t"$7"\t\t\t"$8; print "\nSignature\n"$9;}' | less; clear;;
    [3]* ) sqlite3 Database/hidden_services.db "select * from descriptors_introduction_points" | awk -F"|" '{for(c=0;c<90;c++) printf "-"; print "\nID\tLink_ID\t\tIP_Fingerprint\t\t\t\tIP_Address\tOnion_Port"; print $1"\t"$2"\t\t"$3"\t"$4"\t"$5; print "\nOnion_Key\n"$6; print "\nService_key\n"$7}' | less; clear;;
    [4]* ) sqlite3 Database/hidden_services.db "select * from descriptors_snapshot" | awk -F"|" '{for(c=0;c<82;c++) printf "-"; print "\nID\tLink_ID\t\tDescriptor_Fingerprint\t\t\tDescriptor_Version"; print $1"\t"$2"\t\t"$3"\t"$4; print "\nPublic-Key\n"$5; print "\nSecret-ID\t\t\t\tPublication_time\tProtocol_Version"; print $6"\t"$7"\t"$8; print "\nIntroduction_points\n"$9; print "\nSignature\n"$10;}' | less; clear;;
    [5]* ) sqlite3 Database/hidden_services.db "select * from v3_descriptors" | awk -F"|" 'BEGIN{print "ID\tCERT"} {print $1"\t"$2}' | less; clear;;
    [6]* ) sqlite3 Database/hidden_services.db "select * from extraction_stats;" | awk -F"|" 'BEGIN{print "V2\tV3\tDATE\t\tProcess"} {print $1"\t"$2"\t"$3"\t"$4}' | less; clear;;
    [Qq]* ) exit;;
    * ) clear; echo "Uknown option.";;
  esac
done