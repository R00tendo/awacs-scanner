from termcolor import colored as c
import sys
import os

class throw:
   def no_internet():
      print(c("⦗ERROR ✈💥⦘ No internet connection!", "red"))
      sys.exit()
   def nmap(e):
      print(c("⦗ERROR ✈💥⦘ Error encountered during nmap scan!", "red"))
      print(c(f"⦗ERROR DUMP⦘\n{e}", "red"))
      sys.exit()
   def vulners(e):
      print(c("⦗ERROR ✈💥⦘ Error encountered during vulners exploit search!", "red"))
      print(c(f"⦗ERROR DUMP⦘\n{e}", "red"))
      sys.exit()
   def invalid_scan_type():
      print(c("⦗ERROR ✈💥⦘ You didn't select a valid scan type, the valid scan types are: stealth_flight, vuln_scan, battering_ram.", "red"))
      sys.exit()
   def keyboardinterrupt():
      os.system("clear")
      print(c("⦗ERROR ✈💥⦘ CNTRL+C Pressed! Stopping all scans.", "red"))
      sys.exit()
   def setup():
      print(c("⦗ERROR ✈💥⦘ Your setup is not complete, automatically setting up awacs.", "red"))
      return
   def target_doesnt_exist():
      print(c("⦗ERROR ✈💥⦘ All or one of the targets doesn't exist!", "red"))
      sys.exit()