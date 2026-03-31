#!/bin/bash
BLUE=$(tput setaf 4)
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

echo -e "${BOLD}${BLUE}Resetting auditrs...${NORMAL}"

sudo ./target/debug/auditrs stop

sudo rm -rf /var/log/auditrs/*
sudo rm -rf /etc/auditrs/*
sudo auditctl -D