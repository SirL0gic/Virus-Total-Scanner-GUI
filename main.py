'''
Developed by:
Abis Ali

Twitter: @SirL0gic
Website: thehackersclub.org
'''

#LIBRARY
from tkinter import *
from tkinter import filedialog #for file opemimg
import json
#import nmap3 #pip install python3-nmap
import requests #pip install requests

########################################################
                    #ALL FUNCTIONS START#
########################################################
def test():
    test_label = Label(root, text="Test Complete")
    test_label.grid()
    print("Test Complete")

def exit():
    quit()

def scan_url():
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': '3eff5d05b40c79dc3cd3fb5c05e9bc1bc0bdc0b0dfc0b9c9846ca7daed1f4bd6', 'url':'<url>'}
    params['url'] = input_field.get()
    response = requests.post(url, data=params)
    global scan_id
    scan_id = response.json().get('scan_id')
    print(scan_id)

def get_url():
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': '3eff5d05b40c79dc3cd3fb5c05e9bc1bc0bdc0b0dfc0b9c9846ca7daed1f4bd6', 'resource':'<resource>'}
    params['resource'] = scan_id
    response = requests.get(url, params=params)
    print(response.json())

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
    url_for_report = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': '3eff5d05b40c79dc3cd3fb5c05e9bc1bc0bdc0b0dfc0b9c9846ca7daed1f4bd6', 'resource': 'md5_hash'}
    params['resource'] = md5_hash
    response = requests.get(url_for_report, params=params)
    print(response.json())

#This function creates a window for file scanning
def file_scan_window():
    global file_scan_window
    file_scan_window = Toplevel()
    file_scan_window.geometry("700x400")

    #Init Widgets
    title_2 = Label(file_scan_window, text="TITLE")
    upload_file_button = Button(file_scan_window, text="Upload File", padx=80, pady=80, fg="white", bg="black", command=open_file)
    send_file_button = Button(file_scan_window, text="Send", padx=80, pady=80, fg="white", bg="black", command=scan_file)
    get_file_result_button = Button(file_scan_window, text="Get Result", padx=80, pady=80, fg="white", bg="black", command=get_file)
    exit_button_2 = Button(file_scan_window, text="EXIT", padx=80, pady=20, fg="white", bg="black", command=exit)

    #Display Widgets
    title_2.grid(row=0, column=0)
    upload_file_button.grid(row=1,column=1)
    send_file_button.grid(row=1,column=2)
    get_file_result_button.grid(row=1,column=3)
    exit_button_2.grid(row=7,column=1)


def url_scan_window():
    global url_scan_window
    url_scan_window = Toplevel()
    url_scan_window.geometry("700x400")

    #Init Widgets
    title_3 = Label(url_scan_window, text="TITLE")
    send_url_button = Button(url_scan_window, text="Send", padx=80, pady=80, fg="white", bg="black", command=scan_url)
    get_url_result_button = Button(url_scan_window, text="Get Result", padx=80, pady=80, fg="white", bg="black", command=get_url)
    exit_button_3 = Button(url_scan_window, text="EXIT", padx=80, pady=20, fg="white", bg="black", command=exit)
    global input_field
    input_field = Entry(url_scan_window, width=50, borderwidth=5)

    #Display Widgets
    title_3.grid(row=0, column=0)
    input_field.grid(row=2,column=3)
    send_url_button.grid(row=1,column=1)
    get_url_result_button.grid(row=1,column=3)
    exit_button_3.grid(row=7,column=1)

'''
def vuln_scan_window():
    global vuln_scan_window
    vuln_scan_window = Toplevel()
    vuln_scan_window.geometry("700x400")

    #Init Widgets
    title_4 = Label(vuln_scan_window, text="TITLE")
    global input_field
    input_field = Entry(vuln_scan_window, width=50, borderwidth=5)
    scan_website_button = Button(vuln_scan_window, text="Scan", padx=80, pady=80, fg="white", bg="black", command=nmap_scan)

    #Display Widgets
    title_4.grid(row=0, column=0)
    input_field.grid(row=2,column=3)
    scan_website_button.grid(row=3,column=4)


def nmap_scan():
    nmap = nmap3.Nmap()
    host = input_field.get()
    results = nmap.scan_top_ports(host, args="-sV")
    print(results)
'''

########################################################
                #ALL FUNCTIONS END#
########################################################


#Base Frame (container)
root = Tk()
root.geometry("650x500")

#Root Widgets Init
title = Label(root, text="MaXscan",  font=("Helvetica", 16))
file_scan_button = Button(root, text="File Scan", padx=80, pady=80, fg="white", bg="black", command=file_scan_window)
link_scan_button = Button(root, text="URL Scan", padx=80,pady=80, fg="white", bg="black",command=url_scan_window)
vuln_scan_button = Button(root, text="Vuln Check", padx=80,pady=80, fg="white", bg="black", command=vuln_scan_window)
encrypt_button = Button(root, text="Encryption", padx=80,pady=80, fg="white", bg="black", command=test )
exit_button = Button(root, text="EXIT", padx=80, pady=20, fg="white", bg="black", command=exit)
space = Label(root, text="               ")
space2 = Label(root, text="              ")
space3 = Label(root, text="                ")

#can use hex values for buttons

#Root Widgets Display
title.grid(row=0, column=2)
file_scan_button.grid(row=1,column=1)
space2.grid(row=2,column=1)
link_scan_button.grid(row=3,column=1)
space.grid(row=1,column=2)
vuln_scan_button.grid(row=1,column=6)
encrypt_button.grid(row=3,column=6)
space3.grid(row=6,column=2)
exit_button.grid(row=7,column=2)


#Event Loop
root.mainloop()
