#!/bin/bash
# DevilCorp OWASP 2025 Lab Installer
# Created by L1337XI

echo "[*] Initializing DevilCorp Security Lab Installation..."

# 1. Update and install dependencies
sudo apt-get update -y > /dev/null
sudo apt-get install -y python3 python3-pip git psmisc > /dev/null

# 2. Create directory and download (Assumes you run this after pushing to GitHub)
INSTALL_DIR="/opt/devilcorp"
sudo mkdir -p $INSTALL_DIR
sudo chown $USER:$USER $INSTALL_DIR
cd $INSTALL_DIR

# 3. Clean existing installation
sudo fuser -k 8080/tcp > /dev/null 2>&1

# 4. If directory is empty, clone (Replace with your actual repo URL)
if [ -z "$(ls -A $INSTALL_DIR)" ]; then
    git clone https://github.com/L1337Xi/DevilCorp.git .
fi

# 5. Start the Dynamic Server
nohup python3 server.py > /dev/null 2>&1 &

echo "--------------------------------------------------------"
echo "  DEVILCORP LAB INSTALLED SUCCESSFULLY"
echo "  Access URL: http://$(hostname -I | awk '{print $1}'):8080"
echo "--------------------------------------------------------"
