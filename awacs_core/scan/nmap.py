import subprocess
import socket
from awacs_core.errors import handler
from awacs_core.loading_screens import scanning
from pathlib import Path
import sys
import time


def check_internet():
    internet = False

    try:
     socket.gethostbyname('example.com')
     internet = True
    except:
        pass

    if internet == False:
     try:
        s = socket.socket()
        s.connect('github.com', 80)
        s.close()
        internet = True
     except:
        pass
    return internet


def scan(target, flags):
 if check_internet():
   try: 
    target = target.strip()
    filename = f"{target}_nmap.xml"
    subprocess.check_output(f"nmap {flags} \"{target}\" -oX \"{Path.home()}/.awacs/loot/{filename}\"", shell=True)
   except Exception as e:
    handler.throw.nmap(e)

 else:
     handler.throw.no_internet()
     sys.exit(1)
