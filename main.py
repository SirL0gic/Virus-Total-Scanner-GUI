'''
Developed by:
Abis Ali

Twitter: @SirL0gic
Website: thehackersclub.org
'''

#LIBRARY
from tkinter import *
from tkinter import filedialog #for file opening
from tkinter import ttk
import time
import json
import requests #pip install requests

########################################################
                    #ALL FUNCTIONS START#
########################################################


def scan_url():
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': '3eff5d05b40c79dc3cd3fb5c05e9bc1bc0bdc0b0dfc0b9c9846ca7daed1f4bd6', 'url':'<url>'}
    params['url'] = input_field.get()
    response = requests.post(url, data=params)
    global scan_id
    scan_id = response.json().get('scan_id')
    print(scan_id)

def get_url():
    step2()
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': '3eff5d05b40c79dc3cd3fb5c05e9bc1bc0bdc0b0dfc0b9c9846ca7daed1f4bd6', 'resource':'<resource>'}
    params['resource'] = scan_id
    response = requests.get(url, params=params)
    print("Total number of Engines:")
    print(response.json().get('total'))
    print("Total number of Issues:")
    print(response.json().get('positives'))


def open_file():
    global file_choose
    file_choose = filedialog.askopenfilename()
    print(file_choose)
    return file_choose

def scan_file():
    url_for_scan = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': '3eff5d05b40c79dc3cd3fb5c05e9bc1bc0bdc0b0dfc0b9c9846ca7daed1f4bd6'}
    files = {'file': ("data.txt", open(str(file_choose), 'rb'))}
    response = requests.post(url_for_scan, files=files, params=params)
    global md5_hash
    md5_hash = response.json().get('md5')
    print(md5_hash)

def get_file():
    step()
    url_for_report = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': '3eff5d05b40c79dc3cd3fb5c05e9bc1bc0bdc0b0dfc0b9c9846ca7daed1f4bd6', 'resource': 'md5_hash'}
    params['resource'] = md5_hash
    response = requests.get(url_for_report, params=params)
    print("Total number of Engines:")
    print(response.json().get('total'))
    print("Total number of Issues:")
    print(response.json().get('positives'))


def file_scan_window():
    global file_scan_window
    file_scan_window = Toplevel()
    file_scan_window.geometry("820x400")

    #Init Widgets
    title_2 = Label(file_scan_window, text="File Scanner",font=("Helvetica", 16))
    upload_file_button = Button(file_scan_window, text="Upload", padx=80, pady=50, fg="white", bg="black", command=open_file)
    send_file_button = Button(file_scan_window, text="Scan", padx=80, pady=50, fg="white", bg="black", command=scan_file)
    get_file_result_button = Button(file_scan_window, text="Result", padx=80, pady=50, fg="white", bg="black", command=get_file)
    global bar
    bar = ttk.Progressbar(file_scan_window, orient = HORIZONTAL, length = 400, mode='determinate')
    exit_button_2 = Button(file_scan_window, text="EXIT", padx=80, pady=20, fg="white", bg="black", command=exit)
    space = Label(file_scan_window, text="                         ")
    space2 = Label(file_scan_window, text="                         ")
    space3 = Label(file_scan_window, text="                         ")

    #Display Widgets
    title_2.grid(row=0, column=2)
    space.grid(row=1,column=2)
    bar.grid(row=2,column=2)
    space2.grid(row=3,column=2)
    upload_file_button.grid(row=4,column=1)
    send_file_button.grid(row=4,column=2)
    get_file_result_button.grid(row=4,column=3)
    space3.grid(row=5,column=2)
    exit_button_2.grid(row=7,column=2)

def url_scan_window():
    global url_scan_window
    url_scan_window = Toplevel()
    url_scan_window.geometry("400x400")

    #Init Widgets
    title_3 = Label(url_scan_window, text="URL Scanner", font=("Helvetica", 16))
    send_url_button = Button(url_scan_window, text="Send", padx=80, pady=20, fg="white", bg="black", command=scan_url)
    get_url_result_button = Button(url_scan_window, text="Get", padx=80, pady=20, fg="white", bg="black", command=get_url)
    exit_button_3 = Button(url_scan_window, text="EXIT", padx=80, pady=20, fg="white", bg="black", command=exit)
    global bar
    bar = ttk.Progressbar(url_scan_window, orient = HORIZONTAL, length = 400, mode='determinate')
    global input_field
    input_field = Entry(url_scan_window,text="Enter URL", width=50, borderwidth=5)
    space = Label(url_scan_window, text="" )
    space2 = Label(url_scan_window, text="" )
    space3 = Label(url_scan_window, text="" )
    space4 = Label(url_scan_window, text="" )

    #Display Widgets
    title_3.grid(row=0, column=2)
    space.grid(row=1,column=2)
    bar.grid(row=2,column=2)
    space2.grid(row=3,column=2)
    input_field.grid(row=4,column=2)
    send_url_button.grid(row=5,column=2)
    space4.grid(row=6,column=2)
    get_url_result_button.grid(row=7,column=2)
    space3.grid(row=8,column=2)
    exit_button_3.grid(row=9,column=2)


def step():
    for x in range(5):
        bar['value'] += 10
        file_scan_window.update_idletasks()
        time.sleep(1)

def step2():
    for x in range(5):
        bar['value'] += 10
        url_scan_window.update_idletasks()
        time.sleep(1)

def exit():
    quit()


########################################################
                #ALL FUNCTIONS END#
########################################################


#Base Frame (container)
root = Tk()
root.geometry("630x350")

#Root Widgets Init
title = Label(root, text="Virus Total Desktop",  font=("Helvetica", 16))
file_scan_button = Button(root, text="File Scan", padx=80, pady=80, fg="white", bg="black", command=file_scan_window)
link_scan_button = Button(root, text="URL Scan", padx=80,pady=80, fg="white", bg="black",command=url_scan_window)
exit_button = Button(root, text="EXIT", padx=80, pady=20, fg="white", bg="black", command=exit)
space = Label(root, text="")
space2 = Label(root, text="")
space3 = Label(root, text="")

#can use hex values for buttons

#Root Widgets Display
title.grid(row=0, column=2)
file_scan_button.grid(row=1,column=1)
space2.grid(row=2,column=1)
link_scan_button.grid(row=1,column=3)
space.grid(row=1,column=2)
space3.grid(row=6,column=2)
exit_button.grid(row=7,column=2)


#Event Loop
root.mainloop()
