# -*- coding: utf-8 -*-
"""
Created on Wed Mar 15 11:06:40 2023

@author: Dulantha
"""

import pygame
from pygame import *
import sys
import subprocess
import openpyxl
import textwrap
from tkinter import Tk, filedialog
import json

import socket
import ssl
import argparse
import os
import openai
import PyPDF2
from fpdf import FPDF

import hashlib
import argparse
from time import sleep
from pathlib import Path
from pprint import pprint
import requests

pygame.init()

WINDOW_WIDTH = 760          #Defining the window width 650 initially
WINDOW_HEIGHT = 500			#Defining the window height

MENU_WIDTH = 160				#Setting the Menu width
MENU_HEIGHT = 500			#Setting the Menu height

DASHBOARD_WIDTH = WINDOW_WIDTH - MENU_WIDTH			#Setting the Dashboard width
DASHBOARD_HEIGHT = 600                              #Setting the Dashboard height

pygame.display.set_caption('TOUGHENER')

extra_small_font = pygame.font.SysFont('Arial', 12, bold=True)    #Defining etrax small font
very_small_font = pygame.font.SysFont('Arial', 15, bold=True)
small_font = pygame.font.SysFont('Arial', 20, bold=True)    #Defining small font
medium_font = pygame.font.SysFont('Arial', 23, bold=True)   #Defining medium font
font = pygame.font.Font(None, 20)

menu_button_color = (96, 125, 148)          #Defining the color of the 4 menu buttons

menu_surface = pygame.Surface((MENU_WIDTH, MENU_HEIGHT ))    #defining and coloring the menu surface
menu_surface.fill((54,70,82)) 



dashboard_surface = pygame.Surface((DASHBOARD_WIDTH, DASHBOARD_HEIGHT ))    #defining and coloring the dashboard surface
dashboard_surface.fill((64,83,98))

screen = pygame.display.set_mode((WINDOW_WIDTH, WINDOW_HEIGHT))             #defining the display screen
continue_text = small_font.render('Please Wait....', 10, (0,0,0))
SP_click_text = very_small_font.render('Click on below to Execute the above recommended settings', 10, (255,255,255))

script_path = r'Main.ps1'
command = ['powershell.exe', '-ExecutionPolicy', 'Bypass', '-File', script_path]



menu_title = small_font.render('TOUGENER', 10, 'White')                     #Displaying TOUGHENER at the top
title_surface = pygame.Surface((WINDOW_WIDTH, 40))                          #Defining the backgrounnd of the menu_title
title_surface.fill((56,64,72))



#Drawing the arc for the Threat Score
security_score_arc_rect = pygame.Rect(315, 100, 200, 200)
security_score = 0
security_score_inside = small_font.render('Security Score', 10, 'White') 


security_score_script_path = r'CVSSScore.ps1'
security_score_command = ['powershell.exe', '-ExecutionPolicy', 'Bypass', '-File', security_score_script_path]


#Defining a class for the buttons for easier use
class Button:
    def __init__(self, x, y, width, height, color, text='', text_color=(255,255,255), font_size=26):
        self.rect = pygame.Rect(x, y, width, height)
        self.color = color
        self.text = text
        self.text_color = text_color
        self.font = pygame.font.SysFont(None, font_size)

    def draw(self, surface):
        pygame.draw.rect(surface, self.color, self.rect, border_radius=10)
        if self.text != '':
            text_surface = self.font.render(self.text, True, self.text_color)
            text_rect = text_surface.get_rect(center=self.rect.center)
            surface.blit(text_surface, text_rect)

    def is_clicked(self, event):
        if event.type == pygame.MOUSEBUTTONUP and self.rect.collidepoint(event.pos):
            return True
        else:
            return False




#Defining the 4 menu buttons according to the class defined above

Home = Button(7, MENU_HEIGHT/8 + 40, 140, 55, (96, 125, 148), "Home")
SecurityPolicy = Button(7, MENU_HEIGHT/8 + 110, 140, 55, (96, 125, 148), "Security Policy")
MalwareScan = Button(7, MENU_HEIGHT/8 + 180, 140, 55, (96, 125, 148), "Malware Scan")
NetworkAudit = Button(7, MENU_HEIGHT/8 + 250, 140, 55, (96, 125, 148), "Network Audit")

SPGeneral = Button(DASHBOARD_WIDTH/2 + 50, DASHBOARD_HEIGHT/2 + 120, 130, 40, (96, 125, 148), "Execute Policy") 

NetworkScan = Button(DASHBOARD_WIDTH/2 + 50, DASHBOARD_HEIGHT/2 - 15, 130, 40, (96, 125, 148), "Network Scan")

MalwareFile = Button(DASHBOARD_WIDTH/2 + 50, DASHBOARD_HEIGHT/2 - 15 , 130, 40, (96, 125, 148), "Search File")

SystemScan = Button(DASHBOARD_WIDTH/2 + 50, DASHBOARD_HEIGHT/2 +20 , 130, 40, (96, 125, 148), "System Scan")

menu_buttons = [Home, SecurityPolicy, MalwareScan, NetworkAudit]

current_state = "Home"


SP_section_rect = pygame.Rect(MENU_WIDTH +5, 50 + 30 , DASHBOARD_WIDTH - 10, 300)


#Defining the colors of the buttons to display which is active and which are not
def state_button(menu_buttons,button):
    
    for i in range(4):
        if i == button:
            menu_buttons[i].color = (60, 92, 126)
        
        else:
            menu_buttons[i].color = (96, 125, 148)
    


#Making a pop up dialog box to select the malware file for the malware scanner
def get_file_path():
    # Create a Tkinter root window to show the file dialog
    root = Tk()
    root.withdraw()

    # Show the file dialog and get the selected file path
    file_path = filedialog.askopenfilename()

    # Return the selected file path
    return file_path


file_search_icon = pygame.image.load('FileSearch.png')      #from https://flaticons.net/customize.php?dir=Application&icon=File%20Search.png
MS_click_text = small_font.render("Click on 'Search File' to locate a File to Scan for Malware", 10, (255,255,255))


network_audit_icon = pygame.image.load('NetworkAuditIcon.png')
NA_click_text = small_font.render("Click on 'Network Scan' to execute a scan of the Network", 10, (255,255,255))


home_text = small_font.render("Click on 'System Scan' to execute a scan of the System", 10, (255,255,255))


#reading the excel worksheet
wb = openpyxl.load_workbook('recom.xlsx')
ws = wb['Sheet1']
data_range = ws['A1':'B133']


#Defining the section to display the records in the excel worksheet
SECTION_WIDTH = DASHBOARD_WIDTH - 10
SECTION_HEIGHT = extra_small_font.get_height() * (len(data_range) + 137)       #Defining the section with enough space down to display all records in it

section_surface = pygame.Surface((SECTION_WIDTH, SECTION_HEIGHT)) 
section_surface_top = pygame.Surface((SECTION_WIDTH, 40)) 
section_surface_bottom = pygame.Surface((SECTION_WIDTH, WINDOW_HEIGHT - 380))


section_surface.fill((67, 77, 98))
section_surface_top.fill((64,83,98))
section_surface_bottom.fill((64,83,98))


#Displaying the records in the excel file on the section made for it
SP_x = 10
SP_y = 80

for row in data_range:

    line_counter = 0
    for cell in row:
        
        if len(str(cell.value)) > 45:
            lines = textwrap.wrap(str(cell.value), width=45)
            cur_counter = 0
        
            for line in lines:
                text = extra_small_font.render(line, True, (255,255,255))
                section_surface.blit(text, (SP_x, SP_y))
                SP_y += extra_small_font.get_height()
                cur_counter += 1
            
            SP_y -= (cur_counter * extra_small_font.get_height())

            if cur_counter > line_counter:
                line_counter = cur_counter - 1

            #if len(lines) <= 2:
             #   line_counter -= 1    
            
        
        else:
            text = extra_small_font.render(str(cell.value), True, (255,255,255))
            section_surface.blit(text, (SP_x, SP_y))
            
        SP_x += 300
        
    SP_y += line_counter * extra_small_font.get_height()
    SP_y += extra_small_font.get_height() + 5
    SP_x = 10
    

scroll_pos = 10



#Defining the Heading for Security Policy state
heading1 = small_font.render("Policy", True, (255,255,255))
heading2 = small_font.render("Recommended Setting", True, (255,255,255))

#Rendering it to the top of the section
section_surface_top.blit(heading1, (60, 15))
section_surface_top.blit(heading2, (330, 15))


malware_scanned = False


while True:
    
    screen.blit(menu_surface, (0,0))
    screen.blit(dashboard_surface, (MENU_WIDTH, 0))


    if current_state == "Home":
        #security_score = 450
        screen.blit(home_text, (MENU_WIDTH + 40 , 55))
        SystemScan.draw(screen)

        security_score_percentage = (security_score / 555) * 100
        security_score_percentage = float("{0:.2f}".format(security_score_percentage))
        
        security_score_arc_value = (2 * 3.1416) * (security_score_percentage / 100)
        pygame.draw.arc(screen, (255,255,255), security_score_arc_rect, 0, security_score_arc_value, 15)

        screen.blit(security_score_inside, (340, 165))

        percentage = small_font.render(str(security_score_percentage) + "%", 10, 'White')
        screen.blit(percentage, (390, 210))
    
    
    if current_state == "Security Policy":
        screen.blit(section_surface, (MENU_WIDTH + 5, scroll_pos))
        pygame.draw.rect(screen, (0,0,0) ,SP_section_rect, 1)
        screen.blit(section_surface_top, (MENU_WIDTH + 5, 40))
        screen.blit(section_surface_bottom, (MENU_WIDTH + 5, 380 ))

        screen.blit(SP_click_text, (DASHBOARD_WIDTH/2 - 50, DASHBOARD_HEIGHT/2 + 95))
        SPGeneral.draw(screen)
        
        
    
    if current_state == "Malware Scan":
        MalwareFile.draw(screen)
        screen.blit(file_search_icon, (MENU_WIDTH + DASHBOARD_WIDTH/3 - 35, 90))
        screen.blit(MS_click_text, (MENU_WIDTH + 40 , 55))
    
    
    if current_state == "Network Audit":
        NetworkScan.draw(screen)
        screen.blit(NA_click_text, (MENU_WIDTH + 40, 55))
        screen.blit(network_audit_icon, (MENU_WIDTH + DASHBOARD_WIDTH/3 - 35, 90))
        

    
    screen.blit(title_surface, (0,0))
    screen.blit(menu_title, (113,10))
    
    #state_title = small_font.render(current_state, 10, 'White')
    #screen.blit(state_title, (250, 250))
    
    #text = small_font.render("Hello!", 10, 'White')
    #screen.blit(text, (MENU_WIDTH + DASHBOARD_WIDTH/2, 10))
    
    Home.draw(screen)
    SecurityPolicy.draw(screen)
    MalwareScan.draw(screen)
    NetworkAudit.draw(screen)
    
    x = MENU_WIDTH
    y = 100
    
    """for row in data_range:
        for cell in row:
            text = small_font.render(str(cell.value), True, (255,255,255))
            screen.blit(text, (x, y))
            x += 100
        y += 40
        x = MENU_WIDTH"""
    

    if current_state == "Malware Scan" and malware_scanned == True:
        malware_sha1 = very_small_font.render("SHA1: " + malware_result['hash']['sha1'], True, (255,255,255))
        screen.blit(malware_sha1, (MENU_WIDTH + 80, MENU_HEIGHT - 150))

        malware_sha256 = very_small_font.render("SHA256: " + malware_result['hash']['sha254'], True, (255,255,255))
        screen.blit(malware_sha256, (MENU_WIDTH + 10, MENU_HEIGHT - 123))

        #malware_ctimeout = extra_small_font.render("confirmed-timeout: " + str(malware_result['stats']['confirmed-timeout']), True, (255,255,255))
        #screen.blit(malware_ctimeout, (MENU_WIDTH + 100, MENU_HEIGHT - 130))

        #malware_failure = extra_small_font.render("failure: " + str(malware_result['stats']['failure']), True, (255,255,255))
        #screen.blit(malware_failure, (MENU_WIDTH + 100, MENU_HEIGHT - 113))

        #malware_harmless = extra_small_font.render("harmless: " + str(malware_result['stats']['harmless']), True, (255,255,255))
        #screen.blit(malware_harmless, (MENU_WIDTH + 100, MENU_HEIGHT - 96))        

        malware_malicious = small_font.render("Malicious: " + str(malware_result['stats']['malicious']), True, (255,255,255))
        screen.blit(malware_malicious, (MENU_WIDTH + 100, MENU_HEIGHT - 79))

        #malware_suspicious = extra_small_font.render("suspicious" + str(malware_result['stats']['suspicious']), True, (255,255,255))
        #screen.blit(malware_suspicious, (MENU_WIDTH + 320, MENU_HEIGHT - 130))

        #malware_timeout = extra_small_font.render("timeout: " + str(malware_result['stats']['timeout']), True, (255,255,255))
        #screen.blit(malware_timeout, (MENU_WIDTH + 320, MENU_HEIGHT - 113))

        #malware_tuns = extra_small_font.render("type-unsupported: " + str(malware_result['stats']['type-unsupported']), True, (255,255,255))
        #screen.blit(malware_tuns, (MENU_WIDTH + 320, MENU_HEIGHT - 96))

        malware_undetected = small_font.render("Undetected: " + str(malware_result['stats']['undetected']), True, (255,255,255))
        screen.blit(malware_undetected, (MENU_WIDTH + 320, MENU_HEIGHT - 79))

        #malware_harmless = small_font.render("harmless: " + str(malware_result['votes']['harmless']), True, (255,255,255))
        #screen.blit(malware_harmless, (MENU_WIDTH + 100, MENU_HEIGHT - 59))

        #malware_malicious = small_font.render("Malicious: " + str(malware_result['votes']['malicious']), True, (255,255,255))
        #screen.blit(malware_malicious, (MENU_WIDTH + 320, MENU_HEIGHT - 59))
    
    
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            pygame.quit()

            

        if current_state == "Home" and SystemScan.is_clicked(event):
            
            SystemScan.color = (60, 92, 126)
            SystemScan.draw(screen)
            screen.blit(continue_text, (DASHBOARD_WIDTH/2 + 60, DASHBOARD_HEIGHT/2 + 50))
            pygame.display.update()
            
            ss_process = subprocess.Popen(security_score_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = ss_process.communicate()
            output = output.decode("utf-8")

            security_score = int(output[-4:-1])

            #print(security_score_percentage)
            
            SystemScan.color = (96, 125, 148)
            SystemScan.draw(screen)
            pygame.display.update()


            
        
        if current_state == "Security Policy":
   
            if event.type == pygame.MOUSEBUTTONDOWN and SP_section_rect.collidepoint(event.pos):
               if event.button == 4:
                   # Scroll up
                   scroll_pos = min(0, scroll_pos + 30)
               elif event.button == 5:
                   # Scroll down
                   scroll_pos = max(-(SECTION_HEIGHT - WINDOW_HEIGHT + 110), scroll_pos - 30)
            
                
            
        if current_state == "Malware Scan" and MalwareFile.is_clicked(event):
            MalwareFile.color = (60, 92, 126)
            MalwareFile.draw(screen)
            pygame.display.update()
            file_path = get_file_path()

            #Making the command to excute and then executing it
            malware_command = ['python', 'vtapis.py', file_path]
            malware_process = subprocess.Popen(malware_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = malware_process.communicate()
            print(error.decode("utf-8"))

            malware_output = output.decode("utf-8")

            extracted_output = malware_output[14:malware_output.rfind("}")+1]
            
            #removing \n and \r from it
            extracted_output = extracted_output.replace('\n','').replace('\r','')
            
            malware_result = json.loads(extracted_output.replace("'","\""))
            
            #print(malware_result)

            malware_scanned = True

            #for i in malware_result['hash'].values():
            #    print(i)                                       
            
            MalwareFile.color = (96, 125, 148)
            MalwareFile.draw(screen)
            pygame.display.update()
            
            
        
   
        for i in range(4):
           if menu_buttons[i].is_clicked(event):
               state_button(menu_buttons, i)
               current_state = menu_buttons[i].text


        if SPGeneral.is_clicked(event):

            #In the event the button is clicked,1.It would change its color, 2.Display Please Wait ,3.Execute the script, 4.Change the button color back
            SPGeneral.color = (60, 92, 126)
            SPGeneral.draw(screen)
            screen.blit(continue_text, (DASHBOARD_WIDTH/2 + 60, DASHBOARD_HEIGHT/2 + 165))
            pygame.display.update()
            subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            SPGeneral.color = (96, 125, 148)
            SPGeneral.draw(screen)
            pygame.display.update()



        if current_state == "Network Audit" and NetworkScan.is_clicked(event):
            NetworkScan.color = (60, 92, 126)
            NetworkScan.draw(screen)
            screen.blit(continue_text, (DASHBOARD_WIDTH/2 + 40, DASHBOARD_HEIGHT/2 + 30))
            pygame.display.update()
            
            #subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            sn_command = ['python', 'socket_scanner.py', '127.0.0.1']
            sn_process = subprocess.Popen(sn_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = sn_process.communicate()
            #print(output.decode("utf-8"))

            
            NetworkScan.color = (96, 125, 148)
            NetworkScan.draw(screen)
            pygame.display.update()            


    pygame.display.update()
            
pygame.quit()
