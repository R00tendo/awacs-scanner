# awacs-scanner V2.0.2
<img src="https://user-images.githubusercontent.com/72181445/175283893-5f86ae86-36d0-4b3b-a8b7-6c99b7b1dfa1.png" width=700></img>

## What's awacs-scanner?
awacs-scanner is a fully automated scanner that uses a combination of genocide_engine, nmap, vulners, osint to get as much info and vulnerabilities about a system/systems.

## What's awacs? (Airborne Warning & Control System)

"The Boeing AWACS is positioned to provide mission-critical surveillance support as well as assisting military and civilian authorities in coordinating humanitarian relief." -boeing.com

BTW. awacs-scanner has nothing to do with the actual plane, it is just named that because the plane is used for survaillence, so is awacs-scanner.

## Functions
* Genocide engine
* Python module so you can make a tool yourself with the awacs_core
* vulners api to search for exploits
* searchsploit to search for exploits

## Installation
1. Go to the releases tab
2. Download the latest .deb package
3. `apt install ./awacs_scanner.dev`
4. `awacs`
5. Go to /root/.awacs
6. Put your vulners api key into the file like this: `vulners_api=THE_KEY`
7. Save file

## Usage
```
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Targets/target to scan in one of these formats: divided by "," or file of targets.
  -f FLAGS, --flags FLAGS
                        Nmap flags ("-sV -A")
  --st ST, --scan-type ST
                        stealth_flight, vuln_scan, battering_ram (Read more about scans from github)
  -c CONFIGURATION, --configuration CONFIGURATION
                        Configuration file for awacs scanner (Syntax in github).
```
## Example usage
```
awacs -t target.txt --st stealth_flight
awacs -t example.com -f "-p 21"
awacs -t example1.example.com,example2.example.com --st battering_ram -c config.conf
```
## Scan modes explained
* stealth_flight
  * Syn nmap scan
  * Sesitive file discovery by osint
* vuln_scan (default if none provided)
  * Nmap scan with version detection
  * Use searchsploit to search for exploits
  * Use vulners api to search for exploits 
* battering_ram
  * Full aggressive nmap
  * Full genocide_engine treatment
  * Same as vuln_scan without the nmap one

##Building from source
```
cp -r awacs_core /usr/lib/python3/dist-packages
mv awacs.py /usr/bin/awacs
chmod +x /usr/bin/awacs
awacs
```
