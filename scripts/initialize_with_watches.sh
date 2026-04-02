#!/bin/bash
BLUE=$(tput setaf 4)
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

sudo ./scripts/reset_auditrs.sh

sudo ./target/debug/auditrs start
sudo ./target/debug/auditrs config set format json

sudo ./target/debug/auditrs watch add ./tmp --action read --action write --recursive
sudo ./target/debug/auditrs filter add --record-type EOE --action block

echo -e "\n${BOLD}${BLUE}===========AUDITRS STATE===========${NORMAL}"

echo -e "\n${BOLD}${BLUE}Auditrs rules file:${NORMAL}"
sudo ./target/debug/auditrs config get

echo -e "\n${BOLD}${BLUE}Watches stored in auditrs:${NORMAL}"
sudo ./target/debug/auditrs watch get

echo -e "\n${BOLD}${BLUE}Filters stored in auditrs:${NORMAL}"
sudo ./target/debug/auditrs filter get

echo -e "\n${BOLD}${BLUE}Watches stored in auditctl:${NORMAL}"
sudo auditctl -l    