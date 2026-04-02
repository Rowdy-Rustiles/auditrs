#!/bin/bash
BLUE=$(tput setaf 4)
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo -e "${BOLD}${BLUE}Resetting auditrs...${NORMAL}"

sudo ./target/debug/auditrs stop

sudo rm -rf /var/log/auditrs/*
sudo rm -rf /etc/auditrs/*
sudo auditctl -D