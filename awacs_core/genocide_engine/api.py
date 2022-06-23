from awacs_core.genocide_engine import scanner
from awacs_core.genocide_engine import host_up

def scan(target):
  target=target
  web_threads="40"  
  http = host_up.check2(target, 80) 
  https = host_up.check2(target, 443)
  ssh = host_up.check2(target, 22)
  telnet = host_up.check2(target, 23)
  ftp = host_up.check2(target, 21)
  smtp = host_up.check2(target, 25)
  rpcbind = host_up.check2(target, 110)
  mysql = host_up.check2(target, 3306)
  smb = host_up.check2(target, 445)  
  rdp = host_up.check2(target, 3389)
  resp = scanner.checks(target, http, https, ssh, telnet, ftp, smtp, rpcbind, mysql, smb, rdp, web_threads)
  return resp
