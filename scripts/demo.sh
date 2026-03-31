#!/bin/bash


sudo mkdir -p ./out
sudo ./scripts/initialize_with_watches.sh | tee ./out/demo_output.txt
sudo echo -e "\n" | tee -a ./out/demo_output.txt
sudo ./scripts/trigger_and_view_primary.sh | tee -a ./out/demo_output.txt