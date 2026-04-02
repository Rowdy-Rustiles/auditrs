#!/bin/bash
BLUE=$(tput setaf 4)
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo -e "${BOLD}${BLUE}===========TRIGGERING AUDIT EVENTS===========${NORMAL}"
echo -e "${BOLD}${BLUE}Running ls, mkdir, and touch in ./tmp${NORMAL}"

sudo ls ./tmp &> /dev/null
sudo mkdir ./tmp/test &> /dev/null
sudo touch ./tmp/test/test.txt &> /dev/null
sudo echo "This is some text" > ./tmp/test/test.txt &> /dev/null
sudo echo "This is some more text" > ./tmp/test/test.txt &> /dev/null

sudo echo -e "The following events were called to create this file:\n
\t1. ls ./tmp
\t2. mkdir ./tmp/test
\t3. touch ./tmp/test/test.txt
\t4. echo "This is some text" > ./tmp/test/test.txt
\t5. echo "This is some more text" > ./tmp/test/test.txt" > ./tmp/test/test.txt

echo -e "${BOLD}${BLUE}\nWaiting 4 seconds for the primary log to be written...${NORMAL}"
sleep 4

echo -e "${BOLD}${BLUE}\nPrimary log:${NORMAL}"
sudo ls /var/log/auditrs/primary/
echo -e "\n"


sudo ls /var/log/auditrs/primary/ | head -n 1 | xargs -I {} sudo cat /var/log/auditrs/primary/{}