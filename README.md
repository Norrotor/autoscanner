# Autoscan
A script that automates the process of port scanning and directory brute forcing on web servers!

# Summary
I created this script to automate the repetitive process of scanning HackTheBox machines, as running every command by hand was boring and taking precious time.
The main goal of this script is to automate a part of the enumeration process, running it in the background, so we can focus our attention into other parts of recon or even drink a coffee while we're waiting for it to finish scanning.

# Features
1. **Port scanning**: performs a 'quick' full port scan on the target, then runs deeper (service) scans on the open ports it found.
2. **Directory bruteforcing**: scans for directories and files on ports which have listening web servers. It can also take the ports from files containing nmap scans and scan every one of them.

# Requirements
**nmap**: the tool used for port scanning. You can get the latest version on Debian-based distros using:
```
sudo apt update
sudo apt install nmap
```

**gobuster**: the tool used for directory scanning. You can get the latest version of the tool on Debian-based distros using:
```
sudo apt update
sudo apt install gobuster
```

# Examples of use
```
./autoscan.py dir -p 80 -w big.txt 10.10.10.10
./autoscan.py dir -p 80,8080 -w /usr/share/wordlists/dirb/common.txt 10.10.10.10
./autoscan.py port 10.10.10.10
./autoscan.py port -Pn 10.10.10.10
```

If you want to be able to use it from anywhere on the system, copy it to */usr/local/bin* using:
```
sudo cp ./autoscan.py /usr/local/bin
```

### Pull requests are always welcome :)
