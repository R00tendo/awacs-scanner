from awacs_core.modules.reprint import output
import time
import threading
import sys
import blessed
import os
from termcolor import colored as c

def stop_loadingscreen():
 global stop
 stop = True
 time.sleep(1)

def check_and_correct(steps, max_radar, spaces, max_spaces, step, loading_char):
   global char
   if spaces >= max_spaces:
    spaces = 0

   if steps > max_radar -2:
      step = "up"
    
   if steps < 2:
      step = "down"

   if step == "up":
      char = "◠"
      steps -= 1

   if step == "down":
      char = "◡"
      steps += 1
   
   if loading_char == "◟":
    loading_char = "◜"
   elif loading_char == "◜":
    loading_char = "◝"
   elif loading_char == "◝":
    loading_char = "◞"
   elif loading_char == "◞":
    loading_char = "◟"

   spaces += 1
   return steps,spaces,step,char,loading_char



def check_and_correct_battery(steps, max_radar, spaces, max_spaces, step, loading_char):
   global char
   if spaces >= max_spaces:
    spaces = 0

   if steps > max_radar -2:
      step = "up"
    
   if steps < 2:
      step = "down"

   if step == "up":
      if char == "💥":
        steps = 0
        step = "down"
      char = "💥"

   if step == "down":
      char = "💣"
      steps += 1
   
   if loading_char == "◟":
    loading_char = "◜"
   elif loading_char == "◜":
    loading_char = "◝"
   elif loading_char == "◝":
    loading_char = "◞"
   elif loading_char == "◞":
    loading_char = "◟"

   spaces += 1
   return steps,spaces,step,char,loading_char





def check_and_correct_stealth(steps, max_radar, spaces, max_spaces, step, loading_char):
   global char
   char = ""
   if spaces >= max_spaces:
    spaces = 0
   if loading_char == "◟":
    loading_char = "◜"
   elif loading_char == "◜":
    loading_char = "◝"
   elif loading_char == "◝":
    loading_char = "◞"
   elif loading_char == "◞":
    loading_char = "◟"

   spaces += 1
   return steps,spaces,step,char,loading_char







def loading(target,char,):
 global stop
 term = blessed.Terminal()
 target = target.strip()
 stop = False
 lines = 6
 with output(initial_len=lines, interval=0) as output_lines:

    max_spaces = 11
    spaces = 0
   
    step = "down"

    loading_char = "◟"

    max_radar_steps = 4
    radar_step = 1
    while True:
        
        if stop == True:
            #output_lines[5] = f"{c(f'⦗SCAN DONE⦘ for {target}!', 'cyan', 'on_grey')}\n"
            for i in range(lines):
                output_lines[i] = ""
            break
        
        output_lines[0] = f"{' ' * spaces}{c('✈', 'cyan')}"
        output_lines[radar_step] = f"{' ' * spaces}{char}"
        output_lines[5] = f"{c(f'Scanning {target}!', 'white', 'on_grey', attrs=['blink'])}{c(f' {loading_char} ', 'white', 'on_grey', attrs=['bold'])}"

        for i in range(1,max_radar_steps):
          if radar_step != i:
            output_lines[i] = ' '

        time.sleep(0.5)
        if char == "◡" or char == "◠":
          radar_step,spaces,step,char,loading_char = check_and_correct(radar_step,max_radar_steps,spaces,max_spaces,step,loading_char) 
        elif char == "💣" or char == "💥":
          radar_step,spaces,step,char,loading_char = check_and_correct_battery(radar_step,max_radar_steps,spaces,max_spaces,step,loading_char)
        elif char == "":
          radar_step,spaces,step,char,loading_char = check_and_correct_stealth(radar_step,max_radar_steps,spaces,max_spaces,step,loading_char)
def start_loadingscreen(target, char):
    threading.Thread(target=loading, args=(target,char,)).start()
    return
