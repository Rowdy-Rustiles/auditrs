#!/bin/bash
BLUE=$(tput setaf 4)
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

sudo rm -rf /var/log/auditrs/*
sudo ./target/debug/auditrs reboot

sudo ./scripts/trigger_and_view_primary.sh