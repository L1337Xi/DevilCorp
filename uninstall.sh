#!/bin/bash
# DevilCorp Lab Uninstaller

echo "[*] Removing DevilCorp Lab..."

# 1. Kill the server process
sudo fuser -k 8080/tcp > /dev/null 2>&1

# 2. Remove the directory
sudo rm -rf /opt/devilcorp

echo "[+] DevilCorp has been purged from the system."
