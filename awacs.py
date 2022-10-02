#!/usr/bin/python3
#Awacs vulnerability scanner by @R00tendo
import random
from pathlib import Path
import argparse
import time
import sys
import socket
import os
from xml.dom import minidom
from termcolor import colored as c

try:
    from awacs_core.errors import handler
except:
    print("Initialization Error! Can't import awacs_core, trying to automatically fix the issue.")
    awacs = input("Path to awacs_core:")
    for dire in sys.path:
        if "/usr/lib/python" in dire and "dist-packages" in dire:
            os.system("cp -r " + awacs + " " + dire.strip())
    print("Please restart awacs")
    sys.exit()

from awacs_core.scan import s3_bucket_scanner
from awacs_core.scan import nmap
from awacs_core.xml import xml_parser
from awacs_core.conf import read_conf
from awacs_core.genocide_engine import scanner as genocide_engine_scanner
from awacs_core.genocide_engine import api as genocide_engine_api
from awacs_core.loading_screens import scanning
from awacs_core.files import read_file
from awacs_core.exploit_search import searchsploit
from awacs_core.exploit_search import vulners



logo = c("""
                                             GGGBBBBBBBBBBBBGG
                                     GGMGGMMM               GMMMOMMMG
                                 MPPP                               GGGGGG
                              GM                                         GGGG
                             M                                             GGG
                        :~.               GGHHHH!MMMMMMMMMM                  GG                                     
                        :GG!          GGGG                 GMMM                G                        
                         YGB7                                  MM                                        
                         ~BGBY     .:.                          GG                                     
                         .PGGB5.!YB#&&B?    ...                  G                                   
                        P5BBGGB##&&#BJ~. G*!!G&##B57!.                             :?5?^:.          
                      .7#&&&&#BB##GPY~.FFGHKPL:JGBBBGGY~                        .~YPPP55J?J.        
                 .~JPB&&&&&&&&&&&5JJJYK?^GGEHUFME^7YYJJY^                     ^JPPPGGG5YJ7.         
               YB&&&&&##GPJ7!G&&&GPGGBBGGGJ.KOLBBBBB:J55J.                  :?PGPPPPGPYJ7.           
                .!7~:.        ~G&&###&&GGGGGG.^FFJ5?????^7.                :75GGGP5555YJ?~..           
                                ^P#&&&&&H#G4447GGHGHHHHGGG            .75GBBGGGGGG5J7^^^^~!^:        
                                  :?B&&&&GGGGGGGGG?^.JFF          .!5GBBBBBBBBBPJJ^    .:^^.        
                                     :JG#&&&&@@@&&&&&#5?^.     .!YGBBBBBBBBBBGYJ7.                  
                                        .!5B&&&&&&@&&&&&&BP7:^YGBBBBBBBBBBBB5JJ^                    
                                            ^?P#&&&&&&@&&&&&&#GPPGGGBBBBBBPJ?!                      
                                               .^JG#&&&&&@@&&&&&#BGPPGGGPJ??:                       
                                                 :!5PGB#&&&&&@@&&&&&#BG5??7^^:^~^:.                 
                                            .^7YPGGGGGGGBB#&&&&&&@&&&&&&#BPJ7!^^::.                 
                                        .^?5GGGGGGGGGGGGGGBBB#&&&&&&@@&&&&&&#GY~^                   
                                    .~?5PGPPPP5PPPPPPPGGB##&@@@@##&&&&&&@@&&&&&&BPJ~.               
                                :~?5PPP555555555PPGB#&&@@@&#GJ^. .~JG#&&&&&&@@&&&&&&#P?.            
                           ..!?5PPP555555PPPGB##&@@@&&GY7:           .~5B&&&&&&&&&&@@@&P!           
                      .:!7YPPGGGGGGGGGGB#&&@@@&&BY^^.                    ^?P#&&&&&@@@&#B#G:         
                  .~JPGGGGGGGBBBBB##&@@@@&BJ!^~^:.                          .~JG#&@@@@@@@&#~        
             .^75PGGGGGGGGGGB#&&@@@&GY!:.      .:^^^::^:                        :75#&@@@@@@&.       
         .~?5PGGPPPPGGGB#&&@@&#P?^.               .:~!!^~                           :!75G#GG.       
     .!5PGGGGGBBB##&&@@@&#5!^.                       ..:                                            
       ^5B&&&&&@@@&#PJ~:^^:.                                                                        
         .7B&#PJ!:.      .:^^^:^^.                                                                  
                            :^~!^^~                                                                 
                              .:::  
                AWACS Scanner.                                    CODED BY:@R00tendo                                                                
""", "cyan")


#Scanners
class scanners:
 
 def s3_buckets(domain, threads):
   output = ""
   try:
    buckets = s3_bucket_scanner.scan(domain, wordlist_path, threads)
    output += c("⦗S3 Bucket discovery⦘\n║\n║\n", "cyan")
    for bucket in buckets:
     output += c("╟╴", "cyan") + bucket.strip() + "\n"
   except KeyboardInterrupt:
    handler.throw.keyboardinterrupt()
   return output
 
 def vuln_search(target):
   output = ""
   try:
    output += c("⦗Vulnerabilities⦘\n║\n║\n", "cyan")
    scan_output = xml_parser.parse(f"{Path.home()}/.awacs/loot/{target}_nmap.xml")
    for tech in scan_output:
         exploits_searchsploit = searchsploit.search(tech['name'], tech['version'])
         for exploit in exploits_searchsploit:
            output += f"{c('╟╴', 'cyan')}" + c(f"Affected: {exploit['name']}  Exploit path: {exploit['exploit']}  Source: Searchsploit\n", "yellow")
         if hasattr(session, "vulners_api"):
           try: 
            exploits_vulners = vulners.search(tech['name'], tech['version'], session.vulners_api)
            for exploit in exploits_vulners:
                output += f"{c('╟╴', 'cyan')}" + c(f"Affected: {tech['name']} {tech['version']}  Exploit: {exploit['vhref']}  cvss: {exploit['cvss']['score']}\n", "yellow")
           except Exception as e:
            handler.throw.vulners(e)
         else:
            print(c("⦗VULNERS_API⦘ Api token not found, ignoring", "grey"))
    return output
   except KeyboardInterrupt:
    handler.throw.keyboardinterrupt()

 def genocide_engine(target, char):
   output = ""
   try:
    scanning.start_loadingscreen(target, char)
    lines = genocide_engine_api.scan(target, wordlist_path).split("\n")
    scanning.stop_loadingscreen()
    output += c("⦗Genocide_engine output⦘\n║\n║\n", "cyan")
    for line in lines:
       if len(line) > 0:
        output += f"{c('╟╴','cyan')}{c(line, 'yellow')}\n"
    return output
   except KeyboardInterrupt:
    handler.throw.keyboardinterrupt()


 def nmap(target, flags, char):
   output = ""
   try:
    scanning.start_loadingscreen(target, char)
    nmap.scan(target, flags)
    scanning.stop_loadingscreen()
    output += c("⦗Nmap⦘\n║\n║\n", "cyan")
    nmap_scan = minidom.parse(f"{Path.home()}/.awacs/loot/{target}_nmap.xml")
    ports = nmap_scan.getElementsByTagName('port')
    services = nmap_scan.getElementsByTagName('service')
    for i,port in enumerate(ports):
      if port.hasAttribute('portid'):
       try:
        service = services[i]
        if port.hasAttribute('portid') and service.hasAttribute('name'):
          port_template = c(port.attributes['portid'].value + " " + service.attributes['name'].value,'yellow')
       except:
        port_template = c(port.attributes['portid'].value + " UKNOWN", 'yellow')
       output += f"{c('╟╴Open port:','cyan')}{port_template}\n"
    return output
   except KeyboardInterrupt:
    handler.throw.keyboardinterrupt()
    





def setup():
    handler.throw.setup()
    os.system("apt update")
    os.system("apt install -y golang")
    os.system("apt install -y libmariadb3 libmariadb-dev")
    os.system("apt install -y python3")
    os.system("apt install -y python3-pip")

    os.chdir(Path.home())

    os.mkdir(".awacs")
    os.chdir(".awacs")
    
    os.mkdir("loot")

    open("configuration.conf", "w").write("")
    print(c(f"⦗SUCCESS ✈⦘ Awacs scanner is now successfully installed and set up at {Path.home()}/.awacs. Please run awacs again.", "cyan"))
    sys.exit()

def check_setup():
    good_setup = True
    if not os.path.isdir(f"{Path.home()}/.awacs"):
        good_setup = False
    if not os.path.isdir(f"{Path.home()}/.awacs/loot"):
        good_setup = False
    if not os.path.isfile(f"{Path.home()}/.awacs/configuration.conf"):
        good_setup = False
    if not good_setup:
        setup()


def after_scans():
    os.system("clear")
    print(logo)


#Scan types
def stealth_flight():
  cur_output = ""
  threads = 10
  for target in session.target:
    cur_output += c(f"⦗SCAN RESULTS FOR {target}⦘\n", "cyan")
    #Custom module (non intrusive)
    scanning.start_loadingscreen(target, "")
    lines = genocide_engine_scanner.url_finder(target).split("\n")
    if session.company != "NULL":
     cur_output += scanners.s3_buckets(session.company, threads)
    scanning.stop_loadingscreen()
    after_scans()
    cur_output += c("⦗Genocide_engine output⦘\n║\n║\n", "cyan")
    for line in lines:
       if len(line) > 0:
        cur_output += f"{c('╟╴','cyan')}{c(line, 'yellow')}\n"
    
    
    output = scanners.nmap(target, "-sS -F -T2", "")
    cur_output += output + "\n"
    print(cur_output)

    
    


def vuln_scan():
  cur_output = ""
  for target in session.target:
    cur_output += c(f"⦗SCAN RESULTS FOR {target}⦘\n", "cyan")
    if not session.flags:
      session.flags = "" 
    nmap_output = scanners.nmap(target, f"-Pn -sV -A {session.flags}", "◡")
    vuln_output = scanners.vuln_search(target)
    after_scans()
    cur_output += nmap_output + "\n"
    cur_output += vuln_output + "\n"
    print(cur_output)






def battering_ram():
  cur_output = ""
  
  threads = 50 #Amount of threads used to scan for s3 buckets

  for target in session.target:
    cur_output += c(f"⦗SCAN RESULTS FOR {target}⦘\n", "cyan")
    if not session.flags:
      session.flags = "" 
    genocide_output = scanners.genocide_engine(target, "💣")
    nmap_output = scanners.nmap(target, f"-T4 -p- -sV -A {session.flags}", "💣")
    vuln_output = scanners.vuln_search(target)
    if session.company != "NULL":
     s3_output = scanners.s3_buckets(session.company, threads)
    after_scans()
    cur_output += genocide_output + "\n"
    cur_output += nmap_output + "\n"
    cur_output += vuln_output + "\n"
    if session.company != "NULL":
     cur_output += s3_output + "\n"
    print(cur_output)








#Parse arguments
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Targets/target to scan in one of these formats: divided by \",\" or file of targets.", required=True)
    parser.add_argument("-f", "--flags", help="Nmap flags (\"-sV -A\")")#, required=True)
    parser.add_argument("--st", "--scan-type", help="stealth_flight, vuln_scan, battering_ram  (Read more about scans from github)", default="vuln_scan")
    parser.add_argument("-c", "--configuration", help="Configuration file for awacs scanner (Syntax in github).", default=f"{Path.home()}/.awacs/configuration.conf")
    parser.add_argument("--company", help="Name of the company being scanned. This will be used for s3 bucket scanning (\"NULL\" if it's not a company)", default="NULL")
    args = parser.parse_args()
    return args


def host_up(targets):
    for target in targets:
        try:
            socket.gethostbyname(target)
        except:
            handler.throw.target_doesnt_exist()

#MAIN
def main(args):
   global session, wordlist_path
   
   #Path to the python library eg. /usr/lib/python3/awacs_core
   wordlist_path = nmap.__file__.split("/scan/nmap.py")[0]

   #Main "database" for the target and configuration
   class session:
    None


   #Prerequisities
   if "," not in args.target:
    if os.path.isfile(args.target):
        session.target = []
        for target in read_file.read(args.target):
           session.target.append(target.strip())
    else:
        session.target = [args.target]
   else:
    session.target = args.target.split(",")

   session.configuration = args.configuration
   session.flags = args.flags
   session.scan_type = args.st
   session.company = args.company
   session = read_conf.read(session)
   
   host_up(session.target)

   if session.scan_type.lower() == "stealth_flight": #Done
       stealth_flight()

   elif session.scan_type.lower() == "vuln_scan":
       vuln_scan()

   elif session.scan_type.lower() == "battering_ram":
       battering_ram()   
   else:
       handler.throw.invalid_scan_type()
   




   

if __name__ == "__main__":
   #Very cool logo
   print(logo)
   check_setup()
   args = get_args()
   main(args)
