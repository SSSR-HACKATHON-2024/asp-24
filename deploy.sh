#!/bin/bash
sudo apt update
sudo apt install nmap libqt5sql5-psql python3-psycopg2 python3-psutil python3-requests
sudo mkdir /opt/asp-24
sudo cp -r ./* /opt/asp-24
echo Ready to Roll! Type /opt/asp-24/asp-24s.py -h for help!