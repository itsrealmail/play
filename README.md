apt update&&apt upgrade
apt install masscan nmap curl net-tools pip unzip screen sudo
mkdir z
chmod -R +x z
cd z
wget https://github.com/projectdiscovery/nuclei/releases/download/v3.4.7/nuclei_3.4.7_linux_amd64.zip
unzip nuclei_3.4.7_linux_amd64.zip
chmod +x nuclei
sudo mv nuclei /usr/local/bin/
nuclei -version
rm -rf nuclei_3.4.7_linux_amd64.zip

which masscan
which nmap
which nuclei
------
add play.sh scan.py /tech/ citrix_port.txt web_stats.py

chmod -R +x z
screen -S web
python3 web_stats.py --host 0.0.0.0
ctr+A ctr+D


./play.sh start w1 --ips 145.95.0.1/12 --ports-file citrix_port.txt --services citrix --yaml ./tech/CVE-2019-19781.yaml,./tech/CVE-2025-5777.yaml,./tech/CVE-2023-3519.yaml --threads 5 --checkpoint /tmp/test1_checkpoint.json

./play.sh start w2 --ips 145.95.0.1/16 --ports-file citrix_port.txt --services citrix --yaml ./tech/CVE-2019-19781.yaml,./tech/CVE-2025-5777.yaml,./tech/CVE-2023-3519.yaml --threads 5 --checkpoint /tmp/test1_checkpoint.json

./play.sh start w3 --ips 145.100.0.1/12 --ports-file citrix_port.txt --services citrix --yaml ./tech/CVE-2019-19781.yaml,./tech/CVE-2025-5777.yaml,./tech/CVE-2023-3519.yaml --threads 5 --checkpoint /tmp/test1_checkpoint.json

./play.sh status w3
./play.sh list
./play.sh stop w3