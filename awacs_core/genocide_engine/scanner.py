from ftplib import FTP
import threading
import smbclient
import mariadb
import warnings
import telnetlib
import os
import paramiko
import time
import subprocess
import requests
import random
from awacs_core.scan import nmap

#FTP SECTION!

#FTP Thread
def ftp_brute(combos, host):
   global  feed_back, trets
   wordlist = combos
   for combo in wordlist:
                     combo = combo.strip()
                     combo = combo.split(":")

                     try:
                        ftp = FTP(host, timeout=3)
                        ftp.login(user=combo[0], passwd=combo[1], acct='')
                        ftp.quit()
                        feed_back = feed_back + f"FTP CREDENTIALS CRACKED: username:{combo[0]} password:{combo[1]}\n"
                            
                     except: 
                         pass 
   trets -= 1
def ftp_check(host):
       global trets, feed_back
       feed_back = ""
       #FTP Anonymous login test
       try:
         ftp = FTP(host)
         ftp.login()
         ftp.quit()
         feed_back = feed_back + "FTP ANONYMOUS LOGIN IS ENABLED!" + '\n'
       except:
         pass

       if len(feed_back) >= 0:
              #Initial variables
              wordlist = open(f"{wordlist_path}/genocide_engine/wordlists/ftp-combo.txt").readlines()
              trets = 0
              cache = []
              allowed = 10
             
              #Reads trough wordlist and starts threads
              for line in wordlist:
                     while trets > allowed:
                           time.sleep(0.2)
                     line=line.strip()
                     threading.Thread(target=ftp_brute, args=([line], host)).start()
                     trets += 1
                     
              #Finishing off
              time.sleep(0.5)        
       return feed_back
#FTP BRUTE ENDS








#HTTP/HTTPS File discovery starts here




#Tries to identify the signs of a bad response
def http_wrong_calc(url):
    #You know them, you love them, variables!
    sample_codes = []
    sample_lenghts = []
    which_one = 0
    bad_status = ""
    bad_len = ""


    #Gets an example of the front page (we assume that the main site isn't 404 or 403)
    head = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'
    }

    good = requests.get(url, verify=False)

    #You can increase the samples if you suspect that the site isn't responding correctly all the time
    for i in range(1):


       #Create a made up url address that 99.99999999999999999% doesn't exist
       urla = url + "/" + str(random.randint(1,9999999))

       head = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'
       }
        

      
       a = requests.get(urla, headers=head, verify=False)
       #Compares status code and lenght.
       if a.status_code != good.status_code:
              bad_status = a.status_code
              which_one = 1
       elif a.status_code == good.status_code and len(a.text) != len(good.text):
              bad_len = len(a.text)
              which_one = 2   

    #Returns the results to http_check
    if which_one == 1:
       return which_one, bad_status
    elif which_one == 2:
       return which_one, bad_len

def http_brute_thread(lis, bad, bad_what, url):
    global trets, allowed
    allo = 0
    lsy = 0
    #Checks what mode to detect bad response, the options are from the lenght and from the status_code
    if bad_what == 1:
        bad_status = bad
    elif bad_what == 2:
        bad_len = bad

    #Goes trough the X amount of files in the mini list created by http_brute
    for line in lis:
       #1 second sleep after 8 requests, this helps to not overload requests and no, this is way better than lowering threads since it's not the internet connection but over usage of a library
       lsy += 1
       if lsy > 8:
         time.sleep(1)
         lsy = 0


       line = line.strip()
       requ = False

       #User-Agent to make it look like we're not a bot
       head = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'
       }
       try:
        requ = requests.get(url + "/" + line, headers=head, timeout=4, verify=False)
       except:
         allo += 1
         time.sleep(3)
         if allo > 20:
             trets = 0 
             exit()
  
       #Adds found files to a list that would be turned to a report further down the line
       if requ != False:
        if bad_what == 1:
          if requ.status_code != int(bad_status):
             if "40" not in str(requ.status_code): 
               http_found.append(f"{line} Code:{requ.status_code}")
             else:
               http_found.append(f"{line} Code:{requ.status_code}")
        if bad_what == 2:
          if len(requ) != int(bad_len):
                http_found.append(f"{line} Len:{len(requ.text)}")
   
    trets -= 1
     
   
    return http_found

#Http thread launcher
def http_brute(url, wordlist, bad, bad_what, web_threads):
     global http_found, trets, allowed
     http_found = []
     #Checks if wordlist exists
     if not os.path.exists(wordlist):
          sys.exit(1)
     
     #Loads wordlist and sets up the initial variables
     cache = []
     trets = 0
     lines = open(wordlist, "r").readlines()
     allowed = web_threads

     #Starts threads
     for line in lines:
         line = line.strip()
         cache.append(line)         
         if trets < allowed:
             if len(cache) > 9:
                 trets += 1
                 threading.Thread(target=http_brute_thread, args=(cache, bad, bad_what, url,)).start()
                 cache = []
         while trets >= allowed:
                time.sleep(0.4)
     if len(cache) != 0:
         threading.Thread(target=http_brute_thread, args=(cache, bad, bad_what, url,)).start()
         cache = []
      
     while trets > 0:
         time.sleep(1)
         if len(cache) != 0:
           threading.Thread(target=http_brute_thread, args=(cache, bad, bad_what, url,)).start()
           cache = []
 
     #Generates a report
     amount = 0
     if len(lines) > 2000:
        amount = len(lines)/2
     else:
       amount = len(lines)
     if len(http_found) <= amount:

      http_fdback = ""
      for found in http_found:
            http_fdback = http_fdback + f"{found.strip()}" + '\n'
     else:
        http_fdback = ""
     return http_fdback

#The first step, aka determining what to run and loads wordlists
def http_check(host, p_s, web_threads):
   http_feed_back = ""
   if p_s == "http":
      prefix = "http://"
   elif p_s == "https":
      prefix = "https://"
   host = host.strip()
   url = prefix + host
   try:
    whi, bad = http_wrong_calc(url)
   except:
    return ''
   wordlist = "/usr/lib/python3/dist-packages/awacs_core/genocide_engine/wordlists/http-disco.txt"

   http_feed_back = http_brute(url, wordlist, bad, whi, web_threads)
   return http_feed_back


def http_methods(host, proto):
   url = f"{proto.strip()}://{host}"

   head = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'
   }

   try:
    req = requests.options(url, verify=False, timeout=20, headers=head).headers
   except:
    return ""
   report = ""
   if "Allow" in req:
      methods = req["Allow"]
      methods = methods.split(",")
      for method in methods:
          method = method.strip().lower()
          if method == "put":
               report = report + "The method PUT is listed as an option, this may not be actually allowed but it is listed as an option." + '\n'
          elif method == "delete":
               report = report + "The method DELETE is listed as an option, this may not be actually allowed but it is listed as an option." + '\n'
          elif method == "trace":
               report = report + "The method TRACE is listed as an option, this may not be actually allowed but it is listed as an option." + '\n'
      return report
   else:
     return ""

#HTTP/HTTPS File discovery and methods check stops here



#SSH SECTION STARTS
#ssh thread that tries a list of passwords and usernames
def ssh_brute_thread(host, cache):
    global got, trets
    for combo in cache:
          #Beutifies the user:pass format to variables
          try:
           combo = combo.strip()
           combo = combo.split(":")
           username = combo[0]
           password = combo[1]
           sh = paramiko.SSHClient()
           sh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
          
           sh.connect(host, 22, username, password, timeout=5)
           got.append(f"{username}:{password}")
          except:
             pass
          try:
           sh.close()
          except:
           pass
    trets -= 1
 

#SSH Bruteforce 
def ssh_brute(host):
    global trets, got
    #Initial variables, wordlist
    got = []
    wordlist = "/usr/lib/python3/dist-packages/awacs_core/genocide_engine/wordlists/ssh_combo.txt"
    wordlist = open(wordlist, "r").readlines()
    cache = []
    allowed = 10
    trets = 0
    buff = 10
    #Starts threads 
    for line in wordlist:
        line = line.strip()
        cache.append(line) 
        if allowed >= trets and len(cache) >= buff:
               threading.Thread(target=ssh_brute_thread, args=(host, cache)).start()
               trets += 1
               cache = []
        else:
          while trets >= allowed:
                time.sleep(0.4)
    #thread runs when there are 5 items in cache so if there are for example 22, it will finish off those last 2
    while trets != 0 or len(cache) != 0:
         if len(cache) != 0:
            threading.Thread(target=ssh_brute_thread, args=(host, cache)).start()
            trets += 1
            cache = []
        

    #Report generating
    ssh_feed_back = ""
    for line in got:
          line = line.strip()
          username = line.split(":")[0]
          password = line.split(":")[1]
          ssh_feed_back = ssh_feed_back + f"SSH credentials cracked: Username:{username} Password:{password}" + '\n'
    return ssh_feed_back
  
#SSH SECTION STOPS

#RPCINFO STARTS

#A quick and dirty rpc program info getter, couldn't find any python library for this old service so ill just os lib and trust that the os is not malformed

def rpcinfo_get(host):
   global rpc_info
   info = os.popen(f"rpcinfo \"{host}\"").read()
   info = f" [RPCINFO]\n" + info + " [RPCINFO]\n"
   rpc_info = info
   return rpc_info
#RPCINFO STOPS

#MYSQL SECTION STARTS

#Mysql brute  functions thread that does the actual request
def mysql_brute_thread(host, lis):
   global trets, got
   for line in lis:
      line = line.split(":")
      username = line[0]
      password = line[1]
      try:
       #Mariadb also works for mysql
       conn = mariadb.connect(user=username,password=password,host=host,port=3306,database="mysql")
       conn.close()
       got.append(f"{username}:{password}")
      except:
        pass
   trets -= 1


#Mysql brute thread starter, wordlist reader
def mysql_brute(host):
   global trets, got
   wordlist = open(f"{wordlist_path}/genocide_engine/wordlists/mysql_combo.txt").readlines()
   cache = []
   got = []
   trets = 0
   allowed = 5
   buff = 5
   for line in wordlist:
         line = line.strip()
         cache.append(line)
         if trets < allowed and len(cache) >= buff:
               threading.Thread(target=mysql_brute_thread, args=(host,cache,)).start()
               trets += 1
               cache = []
         else:
            while trets > allowed:
                      time.sleep(0.4)
   while trets != 0 or len(cache) != 0:
     if len(cache) != 0:
         threading.Thread(target=mysql_brute_thread, args=(host,cache,)).start()
         trets += 1
         cache = []
     time.sleep(0.4)
   report = ""
   for rep in got:
        usa = rep.split(":")[0]
        pasa = rep.split(":")[1]
        report = report + f"MYSQL Credentials Cracked: Username:{usa} Password:{pasa}" + '\n'

   return report


#MYSQL SECTION STOPS


#SMB SECTION STARTS

def smb_brute_thread(host, lis):
   global trets, got
   for line in lis:
       line = line.strip()
       user = line.split(":")[0]
       passwd = line.split(":")[1]
       try:
         smbclient.register_session(host, username=user, password=passwd, connection_timeout=10)
         got.append(f"{user}:{passwd}")
         
       except:
         pass
       
   trets -= 1


def smb_anon_scan(host):
     anon = False
     try:  
         smbclient.register_session(host, username="Anonymous", password="Anonymous", connection_timeout=20)
         smbclient.reset_connection_cache()
         print("Anon")
     except Exception as errno:
         if str(errno) == "SMB encryption or signing was required but session was authenticated as a guest which does not support encryption or signing":
           anon = True
     return anon
def smb_brute(host):
    global trets, got
   
    #Scans for anonymous login
    smb_anon = smb_anon_scan(host)

    #SMB BRUTEFORCE
    trets = 0
    got = []
    cache = []
    allowed = 10
    buff = 10
    #Anonymous login makes it hard to detect right and wrong creds
    if not smb_anon:

     wordlist = open(f"{wordlist_path}/genocide_engine/wordlists/smb_combo.txt").readlines()
     
     #Reads wordlist, starts threads
     for line in wordlist:
       line = line.strip()
       cache.append(line)
       if len(cache) >= buff and trets <= allowed:
             threading.Thread(target=smb_brute_thread, args=(host, cache)).start()
             trets += 1
             cache = []
       else:
         while trets >= allowed:
             time.sleep(0.4)
     while trets != 0 or len(cache) != 0:
          if len(cache) != 0:
              threading.Thread(target=smb_brute_thread, args=(host, cache)).start()
              trets += 1
              cache = []


    #Report generating    
    report = ""
    if smb_anon:
        report = report + "SMB ANONYMOUS ACCOUNT IS ENABLED!\n"
 
    if not smb_anon:
     for cred in got:
         username = cred.split(":")[0]
         password = cred.split(":")[1]
         report = report + f"SMB Credentials Cracked: Username: {username} Password: {password}" + '\n'
    return report
#SMB SECTION STOPS





#TELNET SECTION STARTS

def telnet_respond(conn):
         respa = "" 
         while len(respa) < 1:
            respa = conn.read_eager()
            respa = respa.decode("latin-1").strip()
         return respa

def telnet_send(msg, conn):
          msg = bytes(msg + "\n", "latin-1")
          conn.write(msg)
def wait_for(msg, conn):
          respa = "" 
          while msg not in respa.lower():
           respa = telnet_respond(conn)  



def telnet_brute_thread(lis, host):
   global trets, got, fails, fails_max
   try:
    for creds in lis:
      creds = creds.split(":")
      username = creds[0]
      password = creds[1]
      conn = telnetlib.Telnet(host, 23)
      wait_for("login:", conn)
      telnet_send(username, conn)
      wait_for("password:", conn)
      telnet_send(password, conn)
      status = telnet_respond(conn)
      got1 = False
      conn.close()
      if "incorrect" in status:
          pass
      else:
          got1 = True
      if got1:
        got.append(f"{username}:{password}")
   except Exception as e:
      fails += 1
      if fails > fails_max:
         trets = 0
         exit()
   trets -= 1

#Telnet brute thread starter, wordlist reader
def telnet_brute(host):
     global trets, got, fails, fails_max
    
     wordlist = open(f"{wordlist_path}/genocide_engine/wordlists/telnet_combo.txt").readlines()
     cache = []
     fails = 0
     fails_max = len(wordlist)/2
     got = []
     trets = 0
     allowed = 10
     buff = 10
     for line in wordlist:
      line = line.strip()
      cache.append(line)
      if len(cache) >= buff and trets <= allowed:
           threading.Thread(target=telnet_brute_thread, args=(cache, host,)).start()
           trets += 1
           cache = []  
      else:
        while trets >= allowed:
           time.sleep(0.4)

     while trets > 0 or len(cache) != 0:
       if len(cache) != 0:
           threading.Thread(target=telnet_brute_thread, args=(cache, host,)).start()
           cache = []
           trets += 1
     report = ""
     for creds in got:
        creds = creds.split(":")
        username = creds[0]
        password = creds[1]
        report = report + f"Telnet Credentials Cracked: Username:{username} Password:{password}" + '\n'
     return report
#TELNET SECTION ENDS

#URL FINDER
def url_finder(host):
    try:
        Test = wordlist_path
    except:
        globals()['wordlist_path'] = nmap.__file__.split("/scan/nmap.py")[0]
    report = ""
    got = []
    output = subprocess.check_output(f'sigurlfind3r -d  "{host}" -s -iS', shell=True).decode()
    with open(f"{wordlist_path}/genocide_engine/wordlists/extensions") as lines:
        for line in lines:
            line = line.strip()
            for check_against in output.split("\n"):
              if f"http://{host}" in check_against or f"https://{host}" in check_against or f"http://www.{host}" in check_against or f"https://www.{host}" in check_against:
                  if check_against not in got:
                   if line in check_against:
                    got.append(check_against)
                    report += f' [SENSITIVE_FILE] {check_against}' + '\n'
    return report
    
#URL Finder end


#Central hub to decide what scans to run
def checks(host, http, https, ssh, telnet, ftp, smtp, rpcbind, mysql, smb, rdp, web_threads, wordlist_path):
     globals()['wordlist_path'] = wordlist_path
     warnings.filterwarnings(action='ignore')
     only_https = False
     feed_back = ""
     web_threads = int(web_threads)
     #Url finder
     if http != "Fals" or https != "Fals":
        feed_back = feed_back + url_finder(host)

     #Telnet brute...
     if telnet != "Fals":
         feed_back = feed_back + telnet_brute(host)

     #SMB Brute and anon detection
     if smb != "Fals":
          feed_back = feed_back + smb_brute(host)

     #MYSQL Bruteforce 
     if mysql != "Fals":
          feed_back = feed_back + mysql_brute(host)
    
     #Gets rpc programs running
     if rpcbind != "Fals":
           feed_back = feed_back + rpcinfo_get(host)


     #SSH Brute if ssh enabled
     if ssh != "Fals":
        ssh_response = ssh_brute(host)
        feed_back = feed_back + ssh_response





     #FTP scan start if ftp != Fals
     if ftp != "Fals":
       ftp_check_res = ftp_check(host)
       feed_back = feed_back + ftp_check_res









     #HTTP/HTTPS scan or even both if one is open
     if http != "Fals" or https != "Fals":
        if http != "Fals" and https != "Fals":


           #Ran into a problem that is that most sites have http and https ports open but when you goto http, it will redirect you to the https version, this helps to mitigate lost time
           try:
             requests.get(f"http://{host}", allow_redirects=False).headers['Location']
             only_https = True
           except:
                pass
           if only_https: 
               http_s_results = http_check(host, "https", web_threads)
               feed_back = feed_back + http_s_results
               feed_back = feed_back + http_methods(host, "https")





           else:
            #If not a redirect
            p_s = ('http', 'https')
           
            for proto in p_s:
             http_s_results = http_check(host, proto, web_threads)
             feed_back = feed_back + http_s_results
             feed_back = feed_back + http_methods(host, proto)
             

        #Only one running (http/https)
        elif  http != "Fals" or https != "Fals":  

           if http != "Fals":
               p_s = "http"
               http_s_results = http_check(host, p_s, web_threads)
               feed_back = feed_back + http_s_results
               feed_back = feed_back + http_methods(host, p_s)
           elif https != "Fals":
               p_s = "https"
               http_s_results = http_check(host, p_s, web_threads)
               feed_back = feed_back + http_s_results
               feed_back = feed_back + http_methods(host, p_s)
           else:
              sys.exit(1)

           


          
     return feed_back
     exit()
