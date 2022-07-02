import requests
import time
import threading
from termcolor import colored as c

def thread(company):
    global buckets, cur_running
    cur_running += 1

    url = f"http://{company}.s3.amazonaws.com"
    try:
     req = requests.get(url, timeout=5)
    except:
      cur_running -= 1
      exit()
    if req.status_code != 404:
        template = f"{url} {req.status_code}"
        if req.status_code == 403 or req.status_code == 401:
            template = c(template, 'red')
        elif req.status_code == 200:
            template = c(template, 'yellow')
        else:
            template = c(template, 'magenta')
        buckets.append(template)
    cur_running -= 1

def scan(company,wordlist_path,threads):
    global buckets, cur_running
    cur_running = 0
    buckets = []
    wordlist = f"{wordlist_path}/wordlists/s3_fuzz.txt"
    lines = open(wordlist).readlines()
    for line in lines:
        line = line.strip()
        line = line.replace("⦗DOMAIN⦘", company)
        while cur_running >= threads:
            time.sleep(0.5)
        threading.Thread(target=thread, args=(line,)).start()
    while cur_running != 0:
        time.sleep(0.5)
    return buckets
        