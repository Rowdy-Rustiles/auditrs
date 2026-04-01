#!/bin/bash
BLUE=$(tput setaf 4)
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

sudo mkdir -p ./out
sudo ./scripts/initialize_with_watches.sh | tee ./out/demo_output.txt
sudo echo -e "\n" | tee -a ./out/demo_output.txt
sudo ./scripts/trigger_and_view_primary.sh | tee -a ./out/demo_output.txt

echo -e "${BOLD}${BLUE}=============Demo complete=============${NORMAL}"
echo -e "${BOLD}${BLUE}Output saved to ./out/demo_output.txt${NORMAL}"
