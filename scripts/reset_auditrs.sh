#!/bin/bash

sudo ./target/debug/auditrs stop

sudo rm -rf /var/log/auditrs/*
sudo rm -rf /etc/auditrs/*
sudo auditctl -D