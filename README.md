# VimalTotal Virustotal parser
This repo contains all the completed files for my 4th Year Project Thesis

Here is a sample of the raw python code:

import PIL
from PIL import ImageTk
from PIL import Image as PilImage
from tkinter import *
from tkinter import messagebox
from tkinter.filedialog import askopenfilename
import requests
import os
import json
import easygui

/# Packages to be imported into interpreter:
/# Pillow Pillow-PIL PyInstaller easygui requests

/# Original Files in the virtual environment (venv) folder which MUST not be deleted:
/# py.spec, python, vimal logo.png, ViMalTotal_Version_2.py, ViMalTotal_Version_2.spec

/# This is an open source project, it is free to be used and modified. However, I would appreciated if the original
/# developer is cited and the program is referenced in any re-developments.

"""Designed and code by James Finglas, 2019 (with advice from Cathal Murphy)"""

"""Developed to be submitted as part of my Year 4 Thesis project"""

"""Special Acknowledgments to my Course coordinator and module teacher 
   Mr. Stephen O' Shaughnessy, without who's incredible python tuition this
   development project would not have been possible."""

"""If the API key variable has not been set and stored it must be set,
   you must enter you own API key and it must be a valid API key"""


/# Function to create a file to store the global API key for permanence
def makeapifile(apikey):
    with open('api_File.json', 'w') as fp:
        fp.write("{\"apikey\": " + "\"" + str(apikey) + "\"" + "}")


/# check performed to request a valid API key be set.
apikey = ''
switchmode = False
if apikey == '':
    switchmode = True
while switchmode:
    if apikey == '' or apikey is None:
        try:
            apikey = easygui.enterbox(
                "Please enter a valid VirusTotal API Key! Invalid keys will result in API errors!",
                "Your API key cannot be blank!,")
            if apikey is None:
                break
                quitprogram()
            makeapifile(apikey)
        except:
            messagebox.showinfo("API Key cannot be left blank!")
    elif apikey != '':
        switchmode = False


/# define function to maintain count and id of file/hash files
def getapikey():
    if os.path.isfile('api_File.json'):
        with open('api_File.json') as data_file:
            data = json.load(data_file)
        apikey = data["apikey"]
        data_file.close()
        return apikey


/# define function to raise a card to the front of the deck
def raise_frame(frame):
    frame.tkraise()


/# define function to quit the current process
def quitprocess():
    exit(0)


/# define function to output divider line of astrix's
def hashstars():
    Hashreportoutput.insert(END, "****************************************************" + "\n")


/# define function to output new line with blank string
def hashnewline():
    Hashreportoutput.insert(END, "" + "\n")


/# define function to output divider line of astrix's
def scanstars():
    ScanIdReportOutput.insert(END, "****************************************************" + "\n")


/# define function to output new line with blank string
def scannewline():
    ScanIdReportOutput.insert(END, "" + "\n")


/# define function to output divider line of astrix's
def filestars():
    FileIdReportOutput.insert(END, "****************************************************" + "\n")


#/ define function to output new line with blank string
def filenewline():
    FileIdReportOutput.insert(END, "" + "\n")


/# define function to output divider line of astrix's
def urlstars():
    UrlReportOutput.insert(END, "****************************************************" + "\n")


/# define function to output new line with blank string
def urlnewline():
    UrlReportOutput.insert(END, "" + "\n")


/# define function to output divider line of astrix's
def ipstars():
    IPReportOutput.insert(END, "****************************************************" + "\n")


/# define function to output new line with blank string
def ipnewline():
    IPReportOutput.insert(END, "" + "\n")


/# define function to output divider line of astrix's
def domainstars():
    DomainReportOutput.insert(END, "****************************************************" + "\n")


/# define function to output new line with blank string
def domainnewline():
    DomainReportOutput.insert(END, "" + "\n")


/# Function to create Hash scan request confirmation alert box
def hashthank():
    messagebox.showinfo("Thank you!", "Your Hash report request has been submitted")


/# Function to create Hash Report text File generation confirmation alert box
def hashthank2():
    messagebox.showinfo("Thank you!", "Generating Hash report text file!")


/# Function to create Statistics only request confirmation alert box
def stats():
    messagebox.showinfo("Thank you!", "Generating Stats from report!")


/# Function to generate Scan ID report request confirmation message
def scanidthank():
    messagebox.showinfo("Thank you!", "Your Scan ID report request has been submitted")


/# Function to generate scan report text file generation confirmation
def scanidthank2():
    messagebox.showinfo("Thank you!", "Generating Scan ID report text file!")


/# Function to generate new file scan report request confirmation
def filescanthank():
    messagebox.showinfo("Thank you!", "Your File Scan report request has been submitted")


/# Function to generation File report text file generation confirmation message
def filescanthank2():
    messagebox.showinfo("Thank you!", "Generating File report text file!")


/# function to generate URL report request submission confirmation
def urlthank():
    messagebox.showinfo("Thank you!", "Your request for a URL report has been submitted")


/# function to generate URL text file creation confirmation
def urlthank2():
    messagebox.showinfo("Thank you!", "Generating URL ID report text file!")


/# function to generate URL report request submission confirmation
def ipthank():
    messagebox.showinfo("Thank you!", "Your request for an IP report has been submitted")


/# function to generate IP text fil generation confirmation
def ipthank2():
    messagebox.showinfo("Thank you!", "Generating IP ID report text file!")


/# function to generate URL report request submission confirmation
def domainthank():
    messagebox.showinfo("Thank you!", "Your request for a Domain report has been submitted")


/# function to generate domain text fil generation confirmation
def domainthank2():
    messagebox.showinfo("Thank you!", "Generating Domain report text file!")


/# declare root frame
root = Tk()
root.title('ViMal - Total : A  VirusTotal Parser by James Finglas')
root.geometry('556x866')
root.resizable(False, False)

/# Declare frames for card layout
MainMenu = Frame(root, bg='Navy Blue')
Hash = Frame(root, bg='Navy Blue')
ScanID = Frame(root, bg='Navy Blue')
File = Frame(root, bg='Navy Blue')
URL = Frame(root, bg='Navy Blue')
IP = Frame(root, bg='Navy Blue')
Domain = Frame(root, bg='Navy Blue')

/# For loop to to select a frame from a list
for frame in (MainMenu, Hash, ScanID, File, URL, IP, Domain):
    frame.grid(row=1, column=0, sticky='news')

"""########################################## MAIN MENU OPTIONS #####################################################"""

/# The section is where all the GUI element of the Main frame are declared and initialized
img = ImageTk.PhotoImage(PilImage.open('vimal logo.png'))
Label(MainMenu, image=img).pack()
Label(MainMenu, width=60, text='Version 2.0 - Developed With VirusTotal API and Python 3.7', bg='gray').pack()
MainMenuLAbelFrame = LabelFrame(MainMenu, width=60, text='Welcome to the Main Menu', bg='gray')
MainMenuLAbelFrame.pack(expand=1)
Label(MainMenuLAbelFrame, width=60, text='Main Menu', bg='gray').pack()
Label(MainMenu, width=60, text='Please Select from the following options:', bg='gray').pack()
Button(MainMenu, width=57, text='Go to Hash Lookup Page', command=lambda: raise_frame(Hash)).pack()
Button(MainMenu, width=57, text='Go to Scan ID Lookup Page', command=lambda: raise_frame(ScanID)).pack()
Button(MainMenu, width=57, text='Go to File Lookup Page', command=lambda: raise_frame(File)).pack()
Button(MainMenu, width=57, text='Go to URL Lookup Page', command=lambda: raise_frame(URL)).pack()
Button(MainMenu, width=57, text='Go to IP Lookup Page', command=lambda: raise_frame(IP)).pack()
Button(MainMenu, width=57, text='Go to Domain Lookup Page', command=lambda: raise_frame(Domain)).pack()
Button(MainMenu, width=57, text='Exit Program', command=lambda: quitprocess()).pack()
Label(MainMenu, width=60, text='With thanks to Virus-Total For their free use of their amazing API!', bg='gray').pack()

"""##################################################################################################################"""

"""#################################### HASH LOOKUP OPTIONS #########################################################"""

/# The section is where all the GUI elements and functions of the hash lookup page frame are declared and initialized
Label(Hash, width=60, text='Hash Lookup Options', bg='gray').pack()
Button(Hash, width=57, text='Go to Scan ID Lookup Page', command=lambda: raise_frame(ScanID)).pack()
Button(Hash, width=57, text='Go to Main Menu', command=lambda: raise_frame(MainMenu)).pack()
Label(Hash, width=60, text='Hash Report Request: ', bg='gray').pack()
Label(Hash, width=60, text="Please enter the Hash of the Malware you'd like to scan: ", bg='gray').pack()
HashIdTextBox = Entry(Hash, width=60, text="", justify="left")
HashIdTextBox.pack(expand=0)


/# function to request a hash report
def hashfunction(apikey):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    hashuserinput = HashIdTextBox.get()
    params = {'apikey': apikey, 'resource': hashuserinput}
    try:
        response = requests.get(url, params=params).json()
        # ensure text field is epty
        Hashreportoutput.delete(1.0, END)
        # write to text field
        if str(response["response_code"]) != "1":
            Hashreportoutput.insert(END, "An Error Occurred: Hash not found! (Please check if the hash is a valid Hash)"
                                    + "\n")
            Hashreportoutput.insert(END, "" + "\n")
        if 'scan_id' in response:
            hashstars()
            Hashreportoutput.insert(END, "*********************Details************************" + "\n")
            hashstars()
            Hashreportoutput.insert(END, 'Scan ID: ' + str(response["scan_id"] + "\n"))
            hashnewline()
        if 'resource' in response:
            Hashreportoutput.insert(END, 'Resource: ' + str(response["resource"] + "\n"))
            hashnewline()
        if 'permalink' in response:
            Hashreportoutput.insert(END, 'Report Permalink: ' + str(response["permalink"]) + "\n")
            hashnewline()
        if 'verbose_msg' in response:
            Hashreportoutput.insert(END, 'Verbose Message: ' + str(response["verbose_msg"]) + "\n")
            hashnewline()
        if 'positives' in response:
            hashstars()
            Hashreportoutput.insert(END, "*********************Detections*********************" + "\n")
            hashstars()
            hashnewline()
        if 'scans' in response:
            Hashreportoutput.insert(END, "Scans: " + "\n")
            hashnewline()
            # drill down into json sub key scans filed and print values
            for data in response['scans']:
                Hashreportoutput.insert(END, str(data) + ":" + "\n")
                Hashreportoutput.insert(END, "Detected: " + str(response['scans'][data]["detected"]) + "\n")
                Hashreportoutput.insert(END, "Version: " + str(response['scans'][data]["version"]) + "\n")
                Hashreportoutput.insert(END, "Result: " + str(response['scans'][data]["result"]) + "\n")
                Hashreportoutput.insert(END, "Updated last: " + str(response['scans'][data]["update"]) + "\n")
                hashnewline()
        if 'total' in response:
            Hashreportoutput.insert(END, 'Total Engine Detections: ' + str(response["total"]) + "\n")
            hashnewline()
        if 'sha1' in response:
            hashstars()
            Hashreportoutput.insert(END, "************************Sha1 HASH****************" + "\n")
            hashstars()
            Hashreportoutput.insert(END, 'SHA1: ' + str(response["sha1"]) + "\n")
            hashnewline()
        if 'sha256' in response:
            hashstars()
            Hashreportoutput.insert(END, "**********************Sha256 HASH****************" + "\n")
            hashstars()
            Hashreportoutput.insert(END, 'SHA256: ' + str(response["sha256"]) + "\n")
            hashnewline()
        if 'md5' in response:
            hashstars()
            Hashreportoutput.insert(END, "************************MD5**********************" + "\n")
            hashstars()
            Hashreportoutput.insert(END, 'MD5: ' + str(response["md5"]) + "\n")
            hashnewline()
        if 'Positives' in response:
            hashstars()
            Hashreportoutput.insert(END, "*********************Statistics******************" + "\n")
            hashstars()
            Hashreportoutput.insert(END, "Report Statistics: " + "\n")
            Hashreportoutput.insert(END, 'Positive Engine detections: ' + str(response["positives"]) + "\n")
            Hashreportoutput.insert(END, 'Total Engine Detections: ' + str(response["total"]) + "\n")
            hashnewline()
        hashthank()
    except:
        # logic check to determine if the resource parameter has been left blank
        isempty = True
        if hashuserinput == '':
            while isempty:
                messagebox.showinfo("An Error Occurred: ", "A valid Hash must be entered to perform a Hash Lookup! "
                                                           "(Please check if the Hash is a valid Hash)")
                Hashreportoutput.insert(END, "An Error Occurred:Hash not found! (Please check if the Hash is a valid"
                                             "Hash)" + "\n")
                break
                isempty = False
                quitprocess()
        else:
            # logic check to determine if the apikey parameter has been left blank
            apikey = ''
            swtichmode2 = True
            while swtichmode2:
                if apikey == '' or apikey is None:
                    try:
                        apikey = easygui.enterbox("Please enter a valid VirusTotal API Key!",
                                                  "Your API key appears to be invalid! Invalid keys"
                                                  "will result in API errors!")
                        if apikey is None:
                            break
                            quitprocess()
                        makeapifile(apikey)
                    except:
                        messagebox.showinfo("API Key cannot be left blank!")
                elif apikey != '':
                    swtichmode2 = False


Button(Hash, width=57, text='Submit Hash Report Request', command=lambda: hashfunction(getapikey())).pack()


/# define function to maintain count and id of  file/hash files
def makehashfile(event):
    newcounter = 0
    if os.path.isfile('hash_counterFile.json'):
        with open('hash_counterFile.json') as data_file:
            data = json.load(data_file)
        newcounter = data["counter"] + 1
        data_file.close()
        with open('hash_counterFile.json', 'w') as fp:
            fp.write("{\"counter\": " + str(newcounter) + "}")
        fp.close()
    else:
        with open('hash_counterFile.json', 'w') as fp:
            fp.write("{\"counter\": 0}")
    # create file which will be used for file number iteration and maintain file/hash data record
    with open('Hash report ' + str(newcounter), 'w') as fp:
        fp.write(Hashreportoutput.get(1.0, END))
    hashthank2()


/# define function to retrieve stats from desired file/hash report
def displayhashstatsonly(apikey):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    hashuserinput = HashIdTextBox.get()
    params = {'apikey': apikey, 'resource': hashuserinput}
    try:
        response = requests.get(url, params=params).json()
        # ensure text field is empty
        Hashreportoutput.delete(1.0, END)
        # write to text field
        if str(response["response_code"]) != "1":
            Hashreportoutput.insert(END, "An Error Occurred: Hash not found! (Please check if the hash is a valid Hash)"
                                    + "\n")
            hashnewline()
        if 'scan_id' in response:
            hashstars()
            Hashreportoutput.insert(END, "*********************Details*********************" + "\n")
            hashstars()
            Hashreportoutput.insert(END, 'Scan ID: ' + str(response["scan_id"] + "\n"))
            hashnewline()
        if 'resource' in response:
            Hashreportoutput.insert(END, 'Resource: ' + str(response["resource"] + "\n"))
            hashnewline()
        if 'response_code' in response:
            Hashreportoutput.insert(END, 'Response code: ' + str(response["response_code"]) + "\n")
            hashnewline()
        if 'verbose_msg' in response:
            Hashreportoutput.insert(END, 'Verbose Message: ' + str(response["verbose_msg"]) + "\n")
            hashnewline()
        if 'positives' in response:
            hashstars()
            Hashreportoutput.insert(END, "*********************Statistics******************" + "\n")
            hashstars()
            Hashreportoutput.insert(END, "Report Statistics: " + "\n")
            Hashreportoutput.insert(END, 'Positive Engine detections: ' + str(response["positives"]) + "\n")
            Hashreportoutput.insert(END, 'Total Engine Detections: ' + str(response["total"]) + "\n")
            hashnewline()
            hashthank()
    except:
        # logic check to determine if the resource parameter has been left blank
        isempty = True
        if hashuserinput == '':
            while isempty:
                messagebox.showinfo("An Error Occurred: ", "A valid Hash must be entered to perform a Hash Lookup! "
                                                           "(Please check if the Hash is a valid Hash)")
                Hashreportoutput.insert(END,
                                        "An Error Occurred:Hash not found! (Please check if the Hash is a valid"
                                        "Hash)" + "\n")
                break
                isempty = False
                quitprocess()
        else:
            # logic check to determine if the apikey parameter has been left blank
            apikey = ''
            swtichmode2 = True
            while swtichmode2:
                if apikey == '' or apikey is None:
                    try:
                        apikey = easygui.enterbox("Please enter a valid VirusTotal API Key!",
                                                  "Your API key appears to be invalid! Invalid keys"
                                                  "will result in API errors!")
                        if apikey is None:
                            break
                            quitprocess()
                        makeapifile(apikey)
                    except:
                        messagebox.showinfo("API Key cannot be left blank!")
                elif apikey != '':
                    swtichmode2 = False


Label(Hash, width=60, text='Users may use the mouse wheel', bg='gray').pack()
Label(Hash, width=60, text='arrow keys or', bg='gray').pack()
Label(Hash, width=60, text='page up/down buttons to navigate text fields', bg='gray').pack()
Label(Hash, width=60, text='Hash Report Output: ', bg='gray').pack()
Hashreportoutput = Text(Hash, width=60)
Hashreportoutput.pack(expand="yes")
Button(Hash, width=57, text='Display Hash Report Statistics', command=lambda: displayhashstatsonly(getapikey())).pack()
Hashreportfilebtn = Button(Hash, width=57, text='Generate Hash report text file')
Hashreportfilebtn.pack(expand=0)
Hashreportfilebtn.bind('<ButtonRelease-1>', makehashfile)
Button(Hash, width=57, text='Exit Program', command=lambda: quitprocess()).pack()

"""##################################################################################################################"""

"""#################################### Scan ID LOOKUP OPTIONS ######################################################"""

/# The section is where all the GUI element of the Scan ID lookup page frame are declared and initialized
Label(ScanID, width=60, text='Scan ID Lookup Options', bg='gray').pack()
Button(ScanID, width=57, text='Go to File Lookup Page', command=lambda: raise_frame(File)).pack()
Button(ScanID, width=57, text='Go to Main Menu', command=lambda: raise_frame(MainMenu)).pack()
Label(ScanID, width=60, text='Scan ID Report Request: ', bg='gray').pack()
Label(ScanID, width=60, text="Please enter the Scan ID of the Malware you'd like to scan: ", bg='gray').pack()
ScanIdTextBox = Entry(ScanID, width=60, text="", justify="left")
ScanIdTextBox.pack()


/# define function to request a file or hash report
def ScanIdFunction(apikey):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    scanuserinput = ScanIdTextBox.get()
    try:
        params = {'apikey': apikey,
                  'resource': scanuserinput}
        response = requests.get(url, params=params).json()
        # ensure text field is empty
        ScanIdReportOutput.delete(1.0, END)
        # write to text field
        if str(response["response_code"]) != "1":
            ScanIdReportOutput.insert(END, "An Error Occurred: Scan ID report not found!"
                                           "(Please check if the Scan ID is a "
                                           "valid Scan ID)" + "\n")
            scannewline()
        if str(response["response_code"]) == "-2":
            ScanIdReportOutput.insert(END, "Your report has not been compiled, please come back later"
                                           "(Reports can take from 30 secs to 2 minutes to compile)" + "\n")
            scannewline()
        if 'scan_id' in response:
            scanstars()
            ScanIdReportOutput.insert(END, "*********************Details************************" + "\n")
            scanstars()
            ScanIdReportOutput.insert(END, 'Scan ID: ' + str(response["scan_id"] + "\n"))
            scannewline()
        if 'resource' in response:
            ScanIdReportOutput.insert(END, 'Resource: ' + str(response["resource"] + "\n"))
            scannewline()
        if 'permalink' in response:
            ScanIdReportOutput.insert(END, 'Report Permalink: ' + str(response["permalink"]) + "\n")
            scannewline()
        if 'verbose_msg' in response:
            ScanIdReportOutput.insert(END, 'Verbose Message: ' + str(response["verbose_msg"]) + "\n")
            scannewline()
        if 'positives' in response:
            scanstars()
            ScanIdReportOutput.insert(END, "*********************Detections*********************" + "\n")
            scanstars()
            ScanIdReportOutput.insert(END, 'Positive Engine detections: ' + str(response["positives"]) + "\n")
            scannewline()
        if 'scans' in response:
            ScanIdReportOutput.insert(END, "Scans: " + "\n")
            scannewline()

            # drill down into json sub key scans filed and print values
            for data in response['scans']:
                ScanIdReportOutput.insert(END, str(data) + ":" + "\n")
                ScanIdReportOutput.insert(END, "Detected: " + str(response['scans'][data]["detected"]) + "\n")
                ScanIdReportOutput.insert(END, "Version: " + str(response['scans'][data]["version"]) + "\n")
                ScanIdReportOutput.insert(END, "Result: " + str(response['scans'][data]["result"]) + "\n")
                ScanIdReportOutput.insert(END, "Updated last: " + str(response['scans'][data]["update"]) + "\n")
                scannewline()
        if 'total' in response:
            ScanIdReportOutput.insert(END, 'Total Engine Detections: ' + str(response["total"]) + "\n")
            scannewline()
            scannewline()
        if 'sha1' in response:
            scanstars()
            ScanIdReportOutput.insert(END, "************************Sha1 HASH*******************" + "\n")
            scanstars()
            ScanIdReportOutput.insert(END, 'SHA1: ' + str(response["sha1"]) + "\n")
            scannewline()
        if 'sha256' in response:
            scanstars()
            ScanIdReportOutput.insert(END, "**********************Sha256 HASH*******************" + "\n")
            scanstars()
            ScanIdReportOutput.insert(END, 'SHA256: ' + str(response["sha256"]) + "\n")
            scannewline()
        if 'md5' in response:
            scanstars()
            ScanIdReportOutput.insert(END, "************************MD5*************************" + "\n")
            scanstars()
            ScanIdReportOutput.insert(END, 'MD5: ' + str(response["md5"]) + "\n")
            scannewline()
        if 'Positives' in response:
            scanstars()
            ScanIdReportOutput.insert(END, "*********************Statistics*********************" + "\n")
            scanstars()
            ScanIdReportOutput.insert(END, "Report Statistics: " + "\n")
            ScanIdReportOutput.insert(END, 'Positive Engine detections: ' + str(response["positives"]) + "\n")
            ScanIdReportOutput.insert(END, 'Total Engine Detections: ' + str(response["total"]) + "\n")
            scannewline()
        scanidthank()
    except:
        # logic check to determine if the resource parameter has been left blank
        isempty = True
        if scanuserinput == '':
            while isempty:
                messagebox.showinfo("An Error Occurred: ", "A valid Scan ID must be entered to perform a Scan ID "
                                                           "Lookup! (Please check if the Hash is a valid Scan ID)")
                ScanIdReportOutput.insert(END,
                                          "An Error Occurred:Scan ID not found! (Please check if the Scan ID is a valid"
                                          "Scan ID)" + "\n")
                break
                isempty = False
                quitprocess()
        else:
            # logic check to determine if the apikey parameter has been left blank
            apikey = ''
            swtichmode2 = True
            while swtichmode2:
                if apikey == '' or apikey is None:
                    try:
                        apikey = easygui.enterbox("Please enter a valid VirusTotal API Key!",
                                                  "Your API key appears to be invalid! Invalid keys"
                                                  "will result in API errors!")
                        if apikey is None:
                            break
                            quitprocess()
                        makeapifile(apikey)
                    except:
                        messagebox.showinfo("API Key cannot be left blank!")
                elif apikey != '':
                    swtichmode2 = False


/# define function to maintain count and id of ScanID files
def MakeScanIdFile(event):
    newcounter = 0
    if os.path.isfile('ScanId_counterFile.json'):
        with open('ScanId_counterFile.json') as data_file:
            data = json.load(data_file)
        newcounter = data["counter"] + 1
        data_file.close()
        with open('ScanId_counterFile.json', 'w') as fp:
            fp.write("{\"counter\": " + str(newcounter) + "}")
        fp.close()
    else:
        with open('ScanId_counterFile.json', 'w') as fp:
            fp.write("{\"counter\": 0}")
   /# create file which will be used for file number iteration and maintain file/hash data record
    with open('Scan ID report ' + str(newcounter), 'w') as fp:
        fp.write(ScanIdReportOutput.get(1.0, END))
    scanidthank2()


Button(ScanID, width=57, text='Submit Scan ID Report Request', command=lambda: ScanIdFunction(getapikey())).pack()


/# define function to retrieve stats from desired file/hash report
def displayscanidstatsonly(apikey):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    scanuserinput = ScanIdTextBox.get()
    try:
        params = {'apikey': apikey,
                  'resource': scanuserinput}
        response = requests.get(url, params=params).json()
        # ensure text field is empty
        ScanIdReportOutput.delete(1.0, END)
        # write to text field
        if str(response["response_code"]) != "1":
            ScanIdReportOutput.insert(END, "An Error Occurred: Scan ID not found!" \
                                           "(Please check if the Scan ID is a valid Scan ID" + "\n")
            scannewline()
        if str(response["response_code"]) == "-2":
            ScanIdReportOutput.insert(END, "Your report has not been compiled, please come back later"
                                           "(Reports can take from 30 secs to 2 minutes to compile)" + "\n")
            scannewline()
        if 'scan_id' in response:
            scanstars()
            ScanIdReportOutput.insert(END, "*********************Details************************" + "\n")
            scanstars()
            ScanIdReportOutput.insert(END, 'Scan ID: ' + str(response["scan_id"] + "\n"))
            domainstars()
        if 'resource' in response:
            ScanIdReportOutput.insert(END, 'Resource: ' + str(response["resource"] + "\n"))
            domainstars()
        if 'permalink' in response:
            ScanIdReportOutput.insert(END, 'Report Permalink: ' + str(response["permalink"]) + "\n")
            domainstars()
        if 'verbose_msg' in response:
            ScanIdReportOutput.insert(END, 'Verbose Message: ' + str(response["verbose_msg"]) + "\n")
            scannewline()
        if 'positives' in response:
            ScanIdReportOutput.insert(END, "Report Statistics: " + "\n")
            ScanIdReportOutput.insert(END, 'Positive Engine detections: ' + str(response["positives"]) + "\n")
            ScanIdReportOutput.insert(END, 'Total Engine Detections: ' + str(response["total"]) + "\n")
            scannewline()
        stats()
    except:
        # logic check to determine if the resource parameter has been left blank
        isempty = True
        if scanuserinput == '':
            while isempty:
                messagebox.showinfo("An Error Occurred: ", "A valid Scan ID must be entered to perform a Scan ID "
                                                           "Lookup! (Please check if the Hash is a valid Scan ID)")
                ScanIdReportOutput.insert(END,
                                          "An Error Occurred:Scan ID not found! (Please check if the Scan ID is a valid"
                                          "Scan ID)" + "\n")
                break
                isempty = False
                quitprocess()
        else:
            # logic check to determine if the apikey parameter has been left blank
            apikey = ''
            swtichmode2 = True
            while swtichmode2:
                if apikey == '' or apikey is None:
                    try:
                        apikey = easygui.enterbox("Please enter a valid VirusTotal API Key!",
                                                  "Your API key appears to be invalid! Invalid keys"
                                                  "will result in API errors!")
                        if apikey is None:
                            break
                            quitprocess()
                        makeapifile(apikey)
                    except:
                        messagebox.showinfo("API Key cannot be left blank!")
                elif apikey != '':
                    swtichmode2 = False


Label(ScanID, width=60, text='Users may use the mouse wheel', bg='gray').pack()
Label(ScanID, width=60, text='arrow keys or', bg='gray').pack()
Label(ScanID, width=60, text='page up/down buttons to navigate text fields', bg='gray').pack()
Label(ScanID, width=60, text='Scan ID Report Output: ', bg='gray').pack()
ScanIdReportOutput = Text(ScanID, width=60)
ScanIdReportOutput.pack(expand="yes")
Button(ScanID, width=57, text='Display Scan ID Report Statistics',
       command=lambda: displayscanidstatsonly(getapikey())).pack()
ScanIDreportfilebtn = Button(ScanID, width=57, text='Generate ScanID report text file')
ScanIDreportfilebtn.pack(expand=0)
ScanIDreportfilebtn.bind('<ButtonRelease-1>', MakeScanIdFile)
Button(ScanID, width=57, text='Exit Program', command=lambda: quitprocess()).pack()

"""##################################################################################################################"""

"""#################################### FILE LOOKUP OPTIONS #########################################################"""

/# The section is where all the GUI element of the File lookup page frame are declared and initialized
Label(File, width=60, text='File Lookup Options', bg='gray').pack()
Button(File, width=57, text='Go to URL Lookup Page', command=lambda: raise_frame(URL)).pack()
Button(File, width=57, text='Go to Main Menu', command=lambda: raise_frame(MainMenu)).pack()


/# define function to select file you wish to be scanned and request the scan
def fileoutput(apikey):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    fileselection = askopenfilename()
    if fileselection is None:
        quitprocess()
    try:
        if fileselection is None:
            quitprocess()
        params = {'apikey': apikey}
        files = {'file': (fileselection, open(fileselection, 'rb'))}
        response = requests.post(url, files=files, params=params).json()
        /# ensure text area is empty
        FileIdReportOutput.delete(1.0, END)
        /# write to text field
        if str(response["response_code"]) != "1":
            FileIdReportOutput.insert(END, "An Error Occurred: File not found! (Please check if the "
                                           "file selection was not "
                                           "cancelled before the file variable was initialized)" + "\n")
            filenewline()
        if 'scan_id' in response:
            filenewline()
            FileIdReportOutput.insert(END, "*********************Details************************" + "\n")
            filenewline()
            FileIdReportOutput.insert(END, 'Scan ID: ' + str(response["scan_id"] + "\n"))
            filenewline()
        if 'resource' in response:
            FileIdReportOutput.insert(END, 'Resource: ' + str(response["resource"] + "\n"))
            filenewline()
        if 'permalink' in response:
            FileIdReportOutput.insert(END, 'Report Permalink: ' + str(response["permalink"]) + "\n")
            filenewline()
        if 'verbose_msg' in response:
            FileIdReportOutput.insert(END, 'Verbose Message: ' + str(response["verbose_msg"]) + "\n")
            filenewline()
        if 'md5' in response:
            filenewline()
            FileIdReportOutput.insert(END, "************************MD5*************************" + "\n")
            filenewline()
            FileIdReportOutput.insert(END, 'MD5: ' + str(response["md5"]) + "\n")
            filenewline()
        if 'sha1' in response:
            filenewline()
            FileIdReportOutput.insert(END, "************************Sha1************************" + "\n")
            filenewline()
            FileIdReportOutput.insert(END, 'Sha1: ' + str(response["sha1"]) + "\n")
            filenewline()
        if 'sha256' in response:
            filenewline()
            FileIdReportOutput.insert(END, "***********************Sha256***********************" + "\n")
            filenewline()
            FileIdReportOutput.insert(END, 'Sha256: ' + str(response["sha256"]) + "\n")
            filenewline()
        FileIdReportOutput.insert(END, 'How to Retrieve Scan: '
                                  + 'Please wait from 30secs to 2 minutes and use the '
                                    'Hash/Scan ID Lookup Page in the main menu to retrieve '
                                    'your Scan report. The file Scan ID can be found in the '
                                    'application folder in the File Scan ID file that '
                                    'relates to this request.' + "\n")
        filenewline()

        /# create record file of scan data
        with open('File Scan ID File', 'a') as fp:
            # define function to write a divider
            fp.write("**************************New Record******************************")
            fp.write("" + "\n")
            fp.write("The File Scanned was: " + str(response["resource"]) + "\n")
            fp.write("The scan Id is: " + str(response["scan_id"]) + "\n")
            fp.write("The permalink is: " + str(response["permalink"]) + "\n")
            fp.write("The result of the request was: " + str(response["verbose_msg"]) + "\n")
            fp.write("" + "\n")
            fp.write("******************************************************************")
            fp.write("" + "\n")
        filescanthank()
    except:
        # logic check to determine if the resource parameter has been left blank
        isempty = True
        if fileselection == '':
            while isempty:
                messagebox.showinfo("An Error Occurred: ", "A valid file must be entered to request a file scan "
                                                           "Lookup! (Please check if the file is a valid file)")
                FileIdReportOutput.insert(END,
                                          "An Error Occurred:file not found! (Please check if the file is a valid)"
                                          "file)" + "\n")
                break
                isempty = False
                quitprocess()
        else:
            # logic check to determine if the apikey parameter has been left blank
            apikey = ''
            swtichmode2 = True
            while swtichmode2:
                if apikey == '' or apikey is None:
                    try:
                        apikey = easygui.enterbox("Please enter a valid VirusTotal API Key!",
                                                  "Your API key appears to be invalid! Invalid keys"
                                                  "will result in API errors!")
                        if apikey is None:
                            break
                            quitprocess()
                        makeapifile(apikey)
                    except:
                        messagebox.showinfo("API Key cannot be left blank!")
                elif apikey != '':
                    swtichmode2 = False


# define function to maintain count and id of FileScanID files
def makefileidfile():
    newcounter = 0
    if os.path.isfile('FileScanId_counterFile.json'):
        with open('FileScanId_counterFile.json') as data_file:
            data = json.load(data_file)
        newcounter = data["counter"] + 1
        data_file.close()
        with open('FileScanId_counterFile.json', 'w') as fp:
            fp.write("{\"counter\": " + str(newcounter) + "}")
        fp.close()
    else:
        with open('FileScanId_counterFile.json', 'w') as fp:
            fp.write("{\"counter\": 0}")
    # create file which will be used for file number iteration and maintain file/hash data record
    with open('File Scan ID report ' + str(newcounter), 'w') as fp:
        fp.write(FileIdReportOutput.get(1.0, END))


Label(File, width=60, text='Please use the button below to Select a file'
                           'From your drive to be scanned: ', bg='gray').pack()
Button(File, width=57, text='Select file from computer to be scanned', command=lambda: fileoutput(getapikey())).pack()
Label(File, width=60, text='Users may use the mouse wheel', bg='gray').pack()
Label(File, width=60, text='arrow keys or', bg='gray').pack()
Label(File, width=60, text='page up/down buttons to navigate text fields', bg='gray').pack()
Label(File, width=60, text='File Scan Report Output: ', bg='gray').pack()
Label(File, width=60, text='***Reports will not be available for up to 2 minutes', bg='gray').pack()
Label(File, width=60, text='from time of submission!***', bg='gray').pack()
Label(File, width=60, text='***Non Academic API keys can only facilitate 4 Searches per minute*** ', bg='gray').pack()
FileIdReportOutput = Text(File, width=60)
FileIdReportOutput.pack(expand="yes")
FileIDreportfilebtn = Button(File, width=57, text='Generate File scan report text file')
FileIDreportfilebtn.pack(expand=0)
FileIDreportfilebtn.bind('<ButtonRelease-1>', makefileidfile)
Button(File, width=57, text='Exit Program', command=lambda: quitprocess()).pack()

"""##################################################################################################################"""

"""#################################### URL LOOKUP OPTIONS ##########################################################"""

# The section is where all the GUI element of the URL lookup page frame are declared and initialized
Label(URL, width=60, text='URL Lookup Options', bg='gray').pack()
Button(URL, width=57, text='Go to IP Lookup Page', command=lambda: raise_frame(IP)).pack()
Button(URL, width=57, text='Go to Main Menu', command=lambda: raise_frame(MainMenu)).pack()
Label(URL, width=60, text='Please Enter the URL you wish to be scanned (include http://www.): ', bg='gray').pack()
NewUrlScan = Entry(URL, width=60, text="", justify="left")
NewUrlScan.pack()
Label(URL, width=60, text='***Reports will not be available for up to 2 minutes', bg='gray').pack()
Label(URL, width=60, text='from time of submission!***', bg='gray').pack()
Label(URL, width=60, text='***Non Academic API keys can only facilitate 4 Searches per minute*** ', bg='gray').pack()


# define function to output report to URL text field
def newurlscanrequest(apikey):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    myurl = NewUrlScan.get()
    params = {'apikey': apikey, 'url': myurl}
    try:
        response = requests.post(url, data=params).json()
        # ensure text field is empty
        UrlReportOutput.delete(1.0, END)
        # write to text field
        if str(response["response_code"]) != "1":
            UrlReportOutput.insert(END, "An Error Occurred: URL not found! (Please check if the URL is a valid URL)" +
                                   "\n")
        if 'scan_id' in response:
            urlstars()
            UrlReportOutput.insert(END, "*********************Details************************" + "\n")
            urlstars()
            UrlReportOutput.insert(END, 'Scan ID: ' + str(response["scan_id"] + "\n"))
            urlstars()
        if 'resource' in response:
            UrlReportOutput.insert(END, 'Resource: ' + str(response["resource"] + "\n"))
            urlstars()
        if 'scan_date' in response:
            UrlReportOutput.insert(END, 'Scan Date: ' + str(response["scan_date"] + "\n"))
            urlstars()
        if 'url' in response:
            UrlReportOutput.insert(END, 'URL: ' + str(response["url"] + "\n"))
            urlstars()
        if 'permalink' in response:
            UrlReportOutput.insert(END, 'Report Permalink: ' + str(response["permalink"]) + "\n")
            urlstars()
        if 'verbose_msg' in response:
            UrlReportOutput.insert(END, 'Verbose Message: ' + str(response["verbose_msg"]) + "\n")
            UrlReportOutput.insert(END, "" + "\n")

            # create record file of scan data
            with open('URL Scan ID File', 'a') as fp:
                fp.write("**************************New Record******************************")
                fp.write("" + "\n")
                fp.write("The File Scanned was: " + str(response["resource"]) + "\n")
                fp.write("The scan Id is: " + str(response["scan_id"]) + "\n")
                fp.write("The permalink is: " + str(response["permalink"]) + "\n")
                fp.write("The Resource was: " + str(response["resource"]) + "\n")
                fp.write("The result of the request was: " + str(response["verbose_msg"]) + "\n")
                fp.write("" + "\n")
                fp.write("******************************************************************")
                fp.write("" + "\n")
        urlthank()
    except:
        # logic check to determine if the resource parameter has been left blank
        isempty = True
        if myurl == '':
            while isempty:
                messagebox.showinfo("An Error Occurred: ", "A valid URL must be entered to request a URL report "
                                                           "Lookup! (Please check if the URL is a valid URL)")
                UrlReportOutput.insert(END,
                                       "An Error Occurred: URL not found! (Please check if the URL is a valid)"
                                       "file)" + "\n")
                break
                isempty = False
                quitprocess()
        else:
            # logic check to determine if the spikey parameter has been left blank
            apikey = ''
            swtichmode2 = True
            while swtichmode2:
                if apikey == '' or apikey is None:
                    try:
                        apikey = easygui.enterbox("Please enter a valid VirusTotal API Key!",
                                                  "Your API key appears to be invalid! Invalid keys"
                                                  "will result in API errors!")
                        if apikey is None:
                            break
                            quitprocess()
                        makeapifile(apikey)
                    except:
                        messagebox.showinfo("API Key cannot be left blank!")
                elif apikey != '':
                    swtichmode2 = False


Button(URL, width=57, text='Request URL Scan', command=lambda: newurlscanrequest(getapikey())).pack()
Label(URL, width=60, text='Please Enter the Scan ID of the report you wish to request: ', bg='gray').pack()
UrlReportID = Entry(URL, width=60, text="", justify="left")
UrlReportID.pack()


# define function to output report to URL text field
def urlreportrequest(apikey):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    myurl2 = UrlReportID.get()
    params = {'apikey': apikey, 'resource': myurl2}
    try:
        response = requests.get(url, params=params).json()
        # ensure text field is empty
        UrlReportOutput.delete(1.0, END)
        # write to text field
        if str(response["response_code"]) != "1":
            UrlReportOutput.insert(END,
                                   "An Error Occurred: URL not found! (Please check if the URL is a valid URL)" + "\n")
            urlnewline()
        if str(response["response_code"]) == "-2":
            UrlReportOutput.insert(END, "Your report has not been compiled, please come back later (Reports can take "
                                        "from 30 secs to 2 minutes to compile)" + "\n")
            urlnewline()
        if 'scan_id' in response:
            urlstars()
            UrlReportOutput.insert(END, "*********************Details************************" + "\n")
            urlstars()
            UrlReportOutput.insert(END, 'Scan ID: ' + str(response["scan_id"] + "\n"))
            urlnewline()
        if 'resource' in response:
            UrlReportOutput.insert(END, 'Resource: ' + str(response["resource"] + "\n"))
            urlnewline()
        if 'scan_date' in response:
            UrlReportOutput.insert(END, 'Scan Date: ' + str(response["scan_date"] + "\n"))
            urlnewline()
        if 'url' in response:
            UrlReportOutput.insert(END, 'URL: ' + str(response["url"] + "\n"))
            urlnewline()
        if 'permalink' in response:
            UrlReportOutput.insert(END, 'Report Permalink: ' + str(response["permalink"]) + "\n")
            urlnewline()
        if 'verbose_msg' in response:
            UrlReportOutput.insert(END, 'Verbose Message: ' + str(response["verbose_msg"]) + "\n")
            urlnewline()
        if 'filescan_id' in response:
            UrlReportOutput.insert(END, 'Filescan ID: ' + str(response["filescan_id"]) + "\n")
            urlnewline()
        if 'positives' in response:
            urlstars()
            UrlReportOutput.insert(END, "*********************Detections************************" + "\n")
            urlstars()
            UrlReportOutput.insert(END, 'Positive Engine detections: ' + str(response["positives"]) + "\n")
            urlnewline()
        if 'scans' in response:
            UrlReportOutput.insert(END, "Scans: " + "\n")
            urlnewline()
            for data in response['scans']:
                UrlReportOutput.insert(END, "Detected: " + str(response['scans'][data]["detected"]) + "\n")
                UrlReportOutput.insert(END, "Result: " + str(response['scans'][data]["result"]) + "\n")
                if 'detail' in response['scans'][data]:
                    UrlReportOutput.insert(END, "Detail: " + str(response['scans'][data]["detail"]) + "\n")
                urlnewline()
        if 'total' in response:
            UrlReportOutput.insert(END, 'Total Engine Detections: ' + str(response["total"]) + "\n")
            urlnewline()
        urlthank()
    except:
        # logic check to determine if the resource parameter has been left blank
        isempty = True
        if myurl2 == '':
            while isempty:
                messagebox.showinfo("An Error Occurred: ", "A valid URL must be entered to request a URL report "
                                                           "Lookup! (Please check if the URL is a valid URL)")
                UrlReportOutput.insert(END,
                                       "An Error Occurred: URL not found! (Please check if the URL is a valid)"
                                       "file)" + "\n")
                break
                isempty = False
                quitprocess()
        else:
            # logic check to determine if the apikey parameter has been left blank
            apikey = ''
            swtichmode2 = True
            while swtichmode2:
                if apikey == '' or apikey is None:
                    try:
                        apikey = easygui.enterbox("Please enter a valid VirusTotal API Key!",
                                                  "Your API key appears to be invalid! Invalid keys"
                                                  "will result in API errors!")
                        if apikey is None:
                            break
                            quitprocess()
                        makeapifile(apikey)
                    except:
                        messagebox.showinfo("API Key cannot be left blank!")
                elif apikey != '':
                    swtichmode2 = False


Button(URL, width=57, text='Request URL Report', command=lambda: urlreportrequest(getapikey())).pack()


# define function to maintain count and id of URL files
def makeurlfile():
    newcounter = 0
    if os.path.isfile('urlcounterFile.json'):
        with open('urlcounterFile.json') as data_file:
            data = json.load(data_file)
        newcounter = data["counter"] + 1
        data_file.close()
        with open('urlcounterFile.json', 'w') as fp:
            fp.write("{\"counter\": " + str(newcounter) + "}")
        fp.close()
    else:
        with open('urlcounterFile.json', 'w') as fp:
            fp.write("{\"counter\": 0}")
    # write file that will be used to iterate and maintain record of URL data
    with open('URL report ' + str(newcounter), 'w') as fp:
        fp.write(UrlReportOutput.get(1.0, END))
    urlthank2()


# define function to retrieve stats from desired url report
def displayurlstatsonly(apikey):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    myurl3 = UrlReportID.get()
    params = {'apikey': apikey, 'resource': myurl3}
    try:
        response = requests.get(url, params=params).json()
        # ensure text field is empty
        UrlReportOutput.delete(1.0, END)
        # write to text field
        if str(response["response_code"]) != "1":
            UrlReportOutput.insert(END,
                                   "An Error Occurred: URL not found! (Please check if the URL is a valid URL)" + "\n")
            urlnewline()
        if str(response["response_code"]) == "-2":
            UrlReportOutput.insert(END, "Your report has not been compiled, please come back later (Reports can take "
                                        "from 30 secs to 2 minutes to compile)" + "\n")
            urlnewline()
        if 'scan_id' in response:
            urlstars()
            UrlReportOutput.insert(END, "*********************Details************************" + "\n")
            urlstars()
            UrlReportOutput.insert(END, 'Scan ID: ' + str(response["scan_id"] + "\n"))
            urlnewline()
        if 'resource' in response:
            UrlReportOutput.insert(END, 'Resource: ' + str(response["resource"] + "\n"))
            urlnewline()
        if 'url' in response:
            UrlReportOutput.insert(END, 'URL: ' + str(response["url"] + "\n"))
            urlnewline()
        if 'permalink' in response:
            UrlReportOutput.insert(END, 'Report Permalink: ' + str(response["permalink"]) + "\n")
            urlnewline()
        if 'verbose_msg' in response:
            UrlReportOutput.insert(END, 'Verbose Message: ' + str(response["verbose_msg"]) + "\n")
            urlnewline()
        if 'positives' in response:
            urlstars()
            UrlReportOutput.insert(END, "*********************Detections*********************" + "\n")
            urlstars()
            UrlReportOutput.insert(END, "Report Statistics: " + "\n")
            UrlReportOutput.insert(END, 'Positive Engine detections: ' + str(response["positives"]) + "\n")
            UrlReportOutput.insert(END, 'Total Engine Detections: ' + str(response["total"]) + "\n")
            urlnewline()
        stats()
    except:
        # logic check to determine if the resource parameter has been left blank
        isempty = True
        if myurl3 == '':
            while isempty:
                messagebox.showinfo("An Error Occurred: ", "A valid URL must be entered to request a URL report "
                                                           "Lookup! (Please check if the URL is a valid URL)")
                UrlReportOutput.insert(END,
                                       "An Error Occurred: URL not found! (Please check if the URL is a valid)"
                                       "file)" + "\n")
                break
                isempty = False
                quitprocess()
        else:
            # logic check to determine if the apikey parameter has been left blank
            apikey = ''
            swtichmode2 = True
            while swtichmode2:
                if apikey == '' or apikey is None:
                    try:
                        apikey = easygui.enterbox("Please enter a valid VirusTotal API Key!",
                                                  "Your API key appears to be invalid! Invalid keys"
                                                  "will result in API errors!")
                        if apikey is None:
                            break
                            quitprocess()
                        makeapifile(apikey)
                    except:
                        messagebox.showinfo("API Key cannot be left blank!")
                elif apikey != '':
                    swtichmode2 = False


Label(URL, width=60, text='Users may use the mouse wheel', bg='gray').pack()
Label(URL, width=60, text='arrow keys or', bg='gray').pack()
Label(URL, width=60, text='page up/down buttons to navigate text fields', bg='gray').pack()
Label(URL, width=60, text='URL Report Output:', bg='gray').pack()
UrlReportOutput = Text(URL, width=60)
UrlReportOutput.pack(expand="yes")
Button(URL, width=57, text='View URL Report Stats', command=lambda: displayurlstatsonly(getapikey())).pack()
Button(URL, width=57, text='Generate URL report text file', command=lambda: makeurlfile()).pack()
Button(URL, width=57, text='Exit Program', command=lambda: quitprocess()).pack()

"""##################################################################################################################"""

"""#################################### IP LOOKUP OPTIONS ###########################################################"""

# The section is where all the GUI element of the IP lookup page frame are declared and initialized
Label(IP, width=60, text='IP Lookup Options', bg='gray').pack()
Button(IP, width=57, text='Go to Domain Lookup Page', command=lambda: raise_frame(Domain)).pack()
Button(IP, width=57, text='Go to Main Menu', command=lambda: raise_frame(MainMenu)).pack()
Label(IP, width=60, text='Please Enter the IP address you wish to request a report on: ', bg='gray').pack()
NewIPScan = Entry(IP, width=60, text="", justify="left")
NewIPScan.pack()
Label(IP, width=60, text='***Reports will not be available for up to 2 minutes', bg='gray').pack()
Label(IP, width=60, text='from time of submission!***', bg='gray').pack()
Label(IP, width=60, text='***Non Academic API keys can only facilitate 4 Searches per minute*** ', bg='gray').pack()


# define function to output report to URL text field
def ipreportrequest(apikey):
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    newip = NewIPScan.get()
    params = {'apikey': apikey, 'ip': newip}
    isempty = True
    if newip == '':
        while isempty:
            messagebox.showinfo("An Error Occurred: ", "A valid IP must be entered to request a IP report "
                                                       "Lookup! (Please check if the IP is a valid IP)")
            IPReportOutput.insert(END, "An Error Occurred: IP not found! (Please check if the IP is a valid)"
                                       "file)" + "\n")
            break
            isempty = False
            quitprocess()
    elif newip != '':
        try:
            response = requests.get(url, params=params).json()
            # ensure text field is empty
            IPReportOutput.delete(1.0, END)
            # write to text field
            if str(response["response_code"]) != "1":
                IPReportOutput.insert(END, "An Error Occurred: IP address not found! (Please check if the IP address "
                                           "is a valid URL)" + "\n")
                ipnewline()
            if 'network' in response:
                ipstars()
                IPReportOutput.insert(END, "*******************Network Details******************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "Network: " + response["network"] + "\n")
                ipnewline()
            if 'whois' in response:
                ipstars()
                IPReportOutput.insert(END, "*********************WHOIS Details******************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "WHOIS Information: " + response["whois"] + "\n")
                ipnewline()
            if 'dns_records' in response:
                ipstars()
                IPReportOutput.insert(END, "************************DNS Info********************" + "\n")
                ipstars()
                for data in response['dns_records']:
                    IPReportOutput.insert(END, "Type: " + str(data['type']) + "\n")
                    IPReportOutput.insert(END, "Value: " + str(data['value']) + "\n")
                    IPReportOutput.insert(END, "Time To Live: " + str(data['ttl']) + "\n")
                    ipnewline()
                ipnewline()
            if 'resolutions' in response:
                ipstars()
                IPReportOutput.insert(END, "***********Last Resolved DNS resolutions************" + "\n")
                ipstars()
                for data in response['resolutions']:
                    IPReportOutput.insert(END, "Last resolved Date: " + data["last_resolved"] + "\n")
                    ipnewline()
                ipnewline()
            if 'dns_records_date' in response:
                IPReportOutput.insert(END, "DNS Records Date: " + str(response["dns_records_date"]) + "\n")
                ipnewline()
            if 'subdomains' in response:
                ipstars()
                IPReportOutput.insert(END, "**********************Sub Domains*******************" + "\n")
                ipstars()
                for data in response['subdomains']:
                    IPReportOutput.insert(END, str(data) + "\n")
                    ipnewline()
                ipnewline()
            if 'asn' in response:
                ipstars()
                IPReportOutput.insert(END, "************Autonomous System Number****************" + "\n")
                ipstars()
                IPReportOutput.insert(END, 'Autonomous System Number: ' + str(response['asn']) + "\n")
                ipnewline()
            if 'undetected_downloaded_samples' in response:
                ipstars()
                IPReportOutput.insert(END, "*********************Detections*********************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "These are Download samples which return 0 detections" + "\n")
                ipstars()
                for data in response['undetected_downloaded_samples']:
                    IPReportOutput.insert(END, "Detected: " + data["date"] + "\n")
                    IPReportOutput.insert(END, "Scans Results for this date: " + "\n")
                    IPReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    IPReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    IPReportOutput.insert(END, "Sha256: " + str(data["total"]) + "\n")
                    ipnewline()
                ipnewline()
                ipstars()
                IPReportOutput.insert(END, "*These are Download samples which return detections*" + "\n")
                ipstars()
                for data in response['detected_downloaded_samples']:
                    IPReportOutput.insert(END, "Detected: " + data["date"] + "\n")
                    IPReportOutput.insert(END, "Scans Results for this date: " + "\n")
                    IPReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    IPReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    IPReportOutput.insert(END, "Sha256: " + str(data["total"]) + "\n")
                    ipnewline()
                ipnewline()
            if 'undetected_referrer_samples' in response:
                ipstars()
                IPReportOutput.insert(END, "These are Referrer samples which return 0 detections" + "\n")
                ipstars()
                for data in response['undetected_referrer_samples']:
                    IPReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    IPReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    IPReportOutput.insert(END, "Sha256: " + str(data["total"]) + "\n")
                    ipnewline()
                ipnewline()
                ipstars()
                IPReportOutput.insert(END, "*These are Referrer samples which return detections*" + "\n")
                ipstars()
                for data in response['detected_referrer_samples']:
                    IPReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    IPReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    ipnewline()
                ipnewline()
            if 'undetected_urls' in response:
                ipstars()
                IPReportOutput.insert(END, "**These are related URLs which return 0 detections**" + "\n")
                ipstars()
                for data in response['undetected_urls']:
                    IPReportOutput.insert(END, "URL: " + str([data][0][0]) + "\n")
                    IPReportOutput.insert(END, "Hash:" + str([data][0][1]) + "\n")
                    IPReportOutput.insert(END, "Detections: " + str([data][0][2]) + "\n")
                    IPReportOutput.insert(END, "Total: " + str([data][0][3]) + "\n")
                    IPReportOutput.insert(END, "Date: " + str([data][0][4]) + "\n")
                    ipnewline()
                ipnewline()
                ipstars()
                IPReportOutput.insert(END, "***These are related URLs which return detections***" + "\n")
                ipstars()
                for data in response['detected_urls']:
                    IPReportOutput.insert(END, "URL: " + str(data['url']) + "\n")
                    IPReportOutput.insert(END, "Detections: " + str(data['positives']) + "\n")
                    IPReportOutput.insert(END, "Total: " + str(data['total']) + "\n")
                    IPReportOutput.insert(END, "Date: " + str(data['scan_date']) + "\n")
                    ipnewline()
                ipnewline()
            if 'resolutions' in response:
                ipstars()
                IPReportOutput.insert(END, "***********Last Resolved DNS resolutions************" + "\n")
                ipstars()
                for data in response['resolutions']:
                    IPReportOutput.insert(END, "Last resolved Date: " + data["last_resolved"] + "\n")
                    IPReportOutput.insert(END, "Hostname: " + data["hostname"] + "\n")
                    ipnewline()
                ipnewline()
            if 'undetected_communicating_samples' in response:
                ipstars()
                IPReportOutput.insert(END, "**These are Comms samples which return 0 detections*" + "\n")
                ipstars()
                for data in response['undetected_communicating_samples']:
                    IPReportOutput.insert(END, "Detected: " + data["date"] + "\n")
                    IPReportOutput.insert(END, "Scans Results for this date: " + "\n")
                    IPReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    IPReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    IPReportOutput.insert(END, "Sha256: " + str(data["total"]) + "\n")
                    ipnewline()
                ipnewline()
                ipstars()
                IPReportOutput.insert(END, "**These are Comms samples which return detections***" + "\n")
                ipstars()
                for data in response['detected_communicating_samples']:
                    IPReportOutput.insert(END, "Detected: " + data["date"] + "\n")
                    IPReportOutput.insert(END, "Scans Results for this date: " + "\n")
                    IPReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    IPReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    IPReportOutput.insert(END, "Sha256: " + str(data["total"]) + "\n")
                    IPReportOutput.insert(END, '\n')
                ipnewline()
            if 'subject_key_identifier' in response:
                ipstars()
                IPReportOutput.insert(END, "*************Subject Key Identifier*****************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "Subject Key Identifier: " + response["subject_key_identifier"] + "\n")
                ipnewline()
            if 'crl_distribution_points' in response:
                ipstars()
                IPReportOutput.insert(END, "*************CRL Distribution Points****************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "CRL Distribution Points: " + response["crl_distribution_points"] + "\n")
                ipnewline()
            if 'ca_information_access' in response:
                ipstars()
                IPReportOutput.insert(END, "*************CA information Access******************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "CA Information Access: " + response["ca_information_access"] + "\n")
                ipnewline()
            if 'cert_signature' in response:
                ipstars()
                IPReportOutput.insert(END, "******************Cert Signature********************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "Cert Signature: " + response["cert_signature"] + "\n")
                ipnewline()
            if 'serial_number' in response:
                ipstars()
                IPReportOutput.insert(END, "******************Serial Number*********************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "Serial Number: " + response["serial_number"] + "\n")
                ipnewline()
            if 'thumbprint' in response:
                ipstars()
                IPReportOutput.insert(END, "********************Thumbprint**********************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "Thumbprint: " + response["thumbprint"] + "\n")
                ipnewline()
            if 'size' in response:
                ipstars()
                IPReportOutput.insert(END, "***********************Size*************************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "Size: " + data["size"] + "\n")
                ipnewline()
            if 'issuer' in response:
                ipstars()
                IPReportOutput.insert(END, "*********************Issuer*************************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "Issuer: " + response["issuer"] + "\n")
                ipnewline()
            if 'continent' in response:
                ipstars()
                IPReportOutput.insert(END, "********************Continent***********************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "Continent: " + response["continent"] + "\n")
                ipnewline()
            if 'country' in response:
                ipstars()
                IPReportOutput.insert(END, "**********************Country***********************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "Country: " + response["country"] + "\n")
                ipnewline()
            if 'as_owner' in response:
                ipstars()
                IPReportOutput.insert(END, "*******************Owner Details********************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "Owner: " + response["as_owner"] + "\n")
                ipnewline()
            ipthank()
        except:
            # logic check to determine if the apikey parameter has been left blank
            apikey = ''
            swtichmode2 = True
            while swtichmode2:
                if apikey == '' or apikey is None:
                    try:
                        apikey = easygui.enterbox("Please enter a valid VirusTotal API Key!",
                                                  "Your API key appears to be invalid! Invalid keys"
                                                  "will result in API errors!")
                        if apikey is None:
                            break
                            quitprocess()
                        makeapifile(apikey)
                    except:
                        messagebox.showinfo("API Key cannot be left blank!")
                elif apikey != '':
                    swtichmode2 = False


Button(IP, width=57, text='Request IP Report', command=lambda: ipreportrequest(getapikey())).pack()


# define function to maintain count and id of URL files
def makeipfile():
    newcounter = 0
    if os.path.isfile('ipcounterFile.json'):
        with open('ipcounterFile.json') as data_file:
            data = json.load(data_file)
        newcounter = data["counter"] + 1
        data_file.close()
        with open('ipcounterFile.json', 'w') as fp:
            fp.write("{\"counter\": " + str(newcounter) + "}")
        fp.close()
    else:
        with open('ipcounterFile.json', 'w') as fp:
            fp.write("{\"counter\": 0}")
    # write file that will be used to iterate and maintain record of URL data
    with open('IP report ' + str(newcounter), 'w') as fp:
        fp.write(IPReportOutput.get(1.0, END))
    ipthank2()


# define function to retrieve stats from desired url report
def displayipstatsonly(apikey):
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    newip2 = NewIPScan.get()
    params = {'apikey': apikey, 'ip': newip2}
    isempty = True
    if newip2 == '':
        while isempty:
            messagebox.showinfo("An Error Occurred: ", "A valid IP must be entered to request a IP report "
                                                       "Lookup! (Please check if the IP is a valid IP)")
            IPReportOutput.insert(END, "An Error Occurred: IP not found! (Please check if the IP is a valid)"
                                       "file)" + "\n")
            break
            isempty = False
            quitprocess()
    elif newip2 != '':
        try:
            response = requests.get(url, params=params).json()
            # ensure text field is empty
            IPReportOutput.delete(1.0, END)
            # write to text field
            if str(response["response_code"]) != "1":
                IPReportOutput.insert(END, "An Error Occurred: IP address not found! (Please check if the IP address "
                                           "is a valid Ip address)" + "\n")
                ipnewline()
            if 'network' in response:
                ipstars()
                IPReportOutput.insert(END, "*******************Network Details******************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "Network: " + response["network"] + "\n")
                ipnewline()
            if 'undetected_downloaded_samples' in response:
                ipstars()
                IPReportOutput.insert(END, "*********************Detections*********************" + "\n")
                ipstars()
                IPReportOutput.insert(END, "These are Download samples which return 0 detections" + "\n")
                ipstars()
                for data in response['undetected_downloaded_samples']:
                    IPReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    IPReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    IPReportOutput.insert(END, '\n')
                ipnewline()
                ipstars()
                IPReportOutput.insert(END, "*These are Download samples which return detections*" + "\n")
                ipstars()
                for data in response['detected_downloaded_samples']:
                    IPReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    IPReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    IPReportOutput.insert(END, '\n')
                ipnewline()
            if 'undetected_referrer_samples' in response:
                ipstars()
                IPReportOutput.insert(END, "These are Referrer samples which return 0 detections" + "\n")
                ipstars()
                for data in response['undetected_referrer_samples']:
                    IPReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    IPReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    IPReportOutput.insert(END, '\n')
                ipnewline()
                ipstars()
                IPReportOutput.insert(END, "*These are Referrer samples which return detections*" + "\n")
                ipstars()
                for data in response['undetected_referrer_samples']:
                    IPReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    IPReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    IPReportOutput.insert(END, '\n')
                ipnewline()
            if 'undetected_urls' in response:
                ipstars()
                IPReportOutput.insert(END, "**These are related URLs which return 0 detections**" + "\n")
                ipstars()
                for data in response['undetected_urls']:
                    IPReportOutput.insert(END, "URL: " + str([data][0][0]) + "\n")
                    IPReportOutput.insert(END, "Detections: " + str([data][0][2]) + "\n")
                    IPReportOutput.insert(END, "Total: " + str([data][0][3]) + "\n")
                    IPReportOutput.insert(END, '\n')
                ipnewline()
                ipstars()
                IPReportOutput.insert(END, "***These are related URLs which return detections***" + "\n")
                ipstars()
                for data in response['detected_urls']:
                    IPReportOutput.insert(END, "URL: " + str(data['url']) + "\n")
                    IPReportOutput.insert(END, "Detections: " + str(data['positives']) + "\n")
                    IPReportOutput.insert(END, "Total: " + str(data['total']) + "\n")
                    IPReportOutput.insert(END, "Date: " + str(data['scan_date']) + "\n")
                    IPReportOutput.insert(END, '\n')
                ipnewline()
            if 'undetected_communicating_samples' in response:
                ipstars()
                IPReportOutput.insert(END, "**These are Comms samples which return 0 detections*" + "\n")
                ipstars()
                for data in response['undetected_communicating_samples']:
                    IPReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    IPReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    IPReportOutput.insert(END, "Sha256: " + str(data["total"]) + "\n")
                    IPReportOutput.insert(END, '\n')
                ipnewline()
                ipstars()
                IPReportOutput.insert(END, "**These are Comms samples which return detections***" + "\n")
                ipstars()
                for data in response['detected_communicating_samples']:
                    IPReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    IPReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    IPReportOutput.insert(END, '\n')
                ipnewline()
            stats()
        except:
            # logic check to determine if the apikey parameter has been left blank
            apikey = ''
            swtichmode2 = True
            while swtichmode2:
                if apikey == '' or apikey is None:
                    try:
                        apikey = easygui.enterbox("Please enter a valid VirusTotal API Key!",
                                                  "Your API key appears to be invalid! Invalid keys"
                                                  "will result in API errors!")
                        if apikey is None:
                            break
                            quitprocess()
                        makeapifile(apikey)
                    except:
                        messagebox.showinfo("API Key cannot be left blank!")
                elif apikey != '':
                    swtichmode2 = False


Label(IP, width=60, text='Please be aware, IP reports are sourced internally from external sources', bg='gray').pack()
Label(IP, width=60, text='VirusTotal cannot generate new IP scan reports from users', bg='gray').pack()
Label(IP, width=60, text='Users may use the mouse wheel', bg='gray').pack()
Label(IP, width=60, text='arrow keys or', bg='gray').pack()
Label(IP, width=60, text='page up/down buttons to navigate text fields', bg='gray').pack()
Label(IP, width=60, text='IP Report Output', bg='gray').pack()
IPReportOutput = Text(IP, width=60)
IPReportOutput.pack(expand="yes")
Button(IP, width=57, text='View IP Report Stats', command=lambda: displayipstatsonly(getapikey())).pack()
Button(IP, width=57, text='Generate IP report text file', command=lambda: makeipfile()).pack()
Button(IP, width=57, text='Exit Program', command=lambda: quitprocess()).pack()

"""##################################################################################################################"""

"""#################################### DOMAIN LOOKUP OPTIONS #######################################################"""

# The section is where all the GUI element of the Domain lookup page frame are declared and initialized
Label(Domain, width=60, text='Domain Lookup Options').pack()
Button(Domain, width=57, text='Go to Main Menu', command=lambda: raise_frame(MainMenu)).pack()
Label(Domain, width=60, text='Domain Lookup Options', bg='gray').pack()
Button(Domain, width=57, text='Go to Main Menu Page', command=lambda: raise_frame(MainMenu)).pack()
Label(Domain, width=60, text='Please Enter the Domain to request a report on (Include Suffix, .com, .uk, .ie etc): '
                             '', bg='gray').pack()
NewDomainScan = Entry(Domain, width=60, text="", justify="left")
NewDomainScan.pack()
Label(Domain, width=60, text='***Reports will not be available for up to 2 minutes', bg='gray').pack()
Label(Domain, width=60, text='from time of submission!***', bg='gray').pack()
Label(Domain, width=60, text='***Non Academic API keys can only facilitate 4 Searches per minute*** ', bg='gray').pack()


# define function to outputreport to URL text field
def domainreportrequest(apikey):
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    newdomain = NewDomainScan.get()
    params = {'apikey': apikey, 'domain': newdomain}
    isempty = True
    if newdomain == '':
        while isempty:
            messagebox.showinfo("An Error Occurred: ", "A valid Domain must be entered to request a Domain report "
                                                       "Lookup! (Please check if the Domain is a valid Domain)")
            IPReportOutput.insert(END, "An Error Occurred: Domain not found! (Please check if the Domain is a valid)"
                                       "file)" + "\n")
            break
            isempty = False
            quitprocess()
    elif newdomain != '':
        try:
            response = requests.get(url, params=params).json()
            # ensure text field is empty
            DomainReportOutput.delete(1.0, END)
            # write to text field
            if str(response["response_code"]) != "1":
                DomainReportOutput.insert(END, "An Error Occurred: Domain not found! (Please check if the Domain "
                                               "is a valid Domain)" + "\n")
                domainnewline()
            if 'network' in response:
                domainstars()
                DomainReportOutput.insert(END, "***********************Network**********************" + "\n")
                domainstars()
                DomainReportOutput.insert(END, "Network: " + response["network"] + "\n")
                domainnewline()
            if 'whois' in response:
                domainstars()
                DomainReportOutput.insert(END, "**********************WHOIS Info********************" + "\n")
                domainstars()
                DomainReportOutput.insert(END, "WHOIS Information: " + str(response["whois"]) + "\n")
                domainnewline()
            if 'dns_records' in response:
                domainstars()
                DomainReportOutput.insert(END, "************************DNS Info********************" + "\n")
                domainstars()
                for data in response['dns_records']:
                    DomainReportOutput.insert(END, "Type: " + str(data['type']) + "\n")
                    DomainReportOutput.insert(END, "Value: " + str(data['value']) + "\n")
                    DomainReportOutput.insert(END, "Time To Live: " + str(data['ttl']) + "\n")
                    domainnewline()
                domainnewline()
            if 'resolutions' in response:
                domainstars()
                DomainReportOutput.insert(END, "***********Last Resolved DNS resolutions************" + "\n")
                domainstars()
                for data in response['resolutions']:
                    DomainReportOutput.insert(END, "Last resolved Date: " + data["last_resolved"] + "\n")
                    domainnewline()
                domainnewline()
            if 'dns_records_date' in response:
                DomainReportOutput.insert(END, "DNS Records Date: " + str(response["dns_records_date"]) + "\n")
                domainnewline()
            if 'subdomains' in response:
                domainstars()
                DomainReportOutput.insert(END, "**********************Sub Domains*******************" + "\n")
                domainstars()
                for data in response['subdomains']:
                    DomainReportOutput.insert(END, str(data) + "\n")
                    domainnewline()
                domainnewline()
            if 'domain_siblings' in response:
                domainstars()
                DomainReportOutput.insert(END, "**************Un-formatted Domain Siblings**********" + "\n")
                domainstars()
                DomainReportOutput.insert(END, 'Domain Siblings (Un-formatted): ' + str(response['domain_siblings']) + "\n")
                domainnewline()
            if 'https_certificate_date' in response:
                domainstars()
                DomainReportOutput.insert(END, "******************SSL Certificate Date**************" + "\n")
                domainstars()
                DomainReportOutput.insert(END, 'SSL Certificate: ' + str(response['https_certificate_date']) + "\n")
                domainnewline()
            if 'BitDefender category' in response:
                domainstars()
                DomainReportOutput.insert(END, "*******************BitDefender Category*************" + "\n")
                domainstars()
                DomainReportOutput.insert(END, 'BitDefender Category: ' + str(response['BitDefender category']) + "\n")
                domainnewline()
            if 'BitDefender domain info' in response:
                domainstars()
                DomainReportOutput.insert(END, "***************BitDefender Domain Info**************" + "\n")
                domainstars()
                DomainReportOutput.insert(END,
                                          'BitDefender Domain Info: ' + str(response['BitDefender domain info']) + "\n")
                domainnewline()
            if 'undetected_downloaded_samples' in response:
                domainstars()
                DomainReportOutput.insert(END, "*********************Detections*********************" + "\n")
                domainstars()
                DomainReportOutput.insert(END, "These are Download samples which return 0 detections" + "\n")
                domainstars()
                for data in response['undetected_downloaded_samples']:
                    DomainReportOutput.insert(END, "Detected: " + data["date"] + "\n")
                    DomainReportOutput.insert(END, "Scans Results for this date: " + "\n")
                    DomainReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    DomainReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    DomainReportOutput.insert(END, "Sha256: " + str(data["total"]) + "\n")
                    domainnewline()
                domainnewline()
                domainstars()
                DomainReportOutput.insert(END, "*These are Download samples which return detections*" + "\n")
                domainstars()
                domainnewline()
                for data in response['detected_downloaded_samples']:
                    DomainReportOutput.insert(END, "Detected: " + data["date"] + "\n")
                    DomainReportOutput.insert(END, "Scans Results for this date: " + "\n")
                    DomainReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    DomainReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    DomainReportOutput.insert(END, "Sha256: " + str(data["total"]) + "\n")
                    domainnewline()
                domainnewline()
            if 'undetected_referrer_samples' in response:
                domainstars()
                DomainReportOutput.insert(END, "These are Referrer samples which return 0 detections" + "\n")
                domainstars()
                domainnewline()
                for data in response['undetected_referrer_samples']:
                    DomainReportOutput.insert(END, "Detected: " + data["date"] + "\n")
                    DomainReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    DomainReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    DomainReportOutput.insert(END, "Sha256: " + str(data["total"]) + "\n")
                    domainnewline()
                domainnewline()
                domainstars()
                DomainReportOutput.insert(END, "*These are Referrer samples which return detections*" + "\n")
                domainstars()
                domainnewline()
                for data in response['undetected_referrer_samples']:
                    DomainReportOutput.insert(END, "Detected: " + data["date"] + "\n")
                    DomainReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    DomainReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    DomainReportOutput.insert(END, "Sha256: " + str(data["total"]) + "\n")
                    domainnewline()
                domainnewline()
            if 'undetected_urls' in response:
                domainstars()
                DomainReportOutput.insert(END, "**These are related URLs which return 0 detections**" + "\n")
                domainstars()
                domainnewline()
                for data in response['undetected_urls']:
                    DomainReportOutput.insert(END, "URL: " + str([data][0][0]) + "\n")
                    DomainReportOutput.insert(END, "Hash:" + str([data][0][1]) + "\n")
                    DomainReportOutput.insert(END, "Detections: " + str([data][0][2]) + "\n")
                    DomainReportOutput.insert(END, "Total: " + str([data][0][3]) + "\n")
                    DomainReportOutput.insert(END, "Date: " + str([data][0][4]) + "\n")
                    domainnewline()
                domainnewline()
                domainstars()
                DomainReportOutput.insert(END, "***These are related URLs which return detections***" + "\n")
                domainstars()
                domainnewline()
                for data in response['detected_urls']:
                    DomainReportOutput.insert(END, "URL: " + str(data['url']) + "\n")
                    DomainReportOutput.insert(END, "Detections: " + str(data['positives']) + "\n")
                    DomainReportOutput.insert(END, "Total: " + str(data['total']) + "\n")
                    DomainReportOutput.insert(END, "Date: " + str(data['scan_date']) + "\n")
                    domainnewline()
                domainnewline()
            if 'undetected_communicating_samples' in response:
                domainstars()
                DomainReportOutput.insert(END, "**These are Comms samples which return 0 detections*" + "\n")
                domainstars()
                domainnewline()
                for data in response['undetected_communicating_samples']:
                    DomainReportOutput.insert(END, "Detected: " + data["date"] + "\n")
                    DomainReportOutput.insert(END, "Scans Results for this date: " + "\n")
                    DomainReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    DomainReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    DomainReportOutput.insert(END, "Sha256: " + str(data["total"]) + "\n")
                    domainnewline()
                domainnewline()
                domainstars()
                DomainReportOutput.insert(END, "**These are Comms samples which return detections***" + "\n")
                domainstars()
                for data in response['detected_communicating_samples']:
                    DomainReportOutput.insert(END, "Detected: " + data["date"] + "\n")
                    DomainReportOutput.insert(END, "Scans Results for this date: " + "\n")
                    DomainReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    DomainReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    DomainReportOutput.insert(END, "Sha256: " + str(data["total"]) + "\n")
                    domainnewline()
                domainnewline()
            if 'Alexa' in response:
                domainstars()
                DomainReportOutput.insert(END, "********************Alexa Data**********************" + "\n")
                domainstars()
                DomainReportOutput.insert(END, "Alexa: " + str(response["Alexa"]) + "\n")
                domainnewline()
            if 'Alexa category' in response:
                DomainReportOutput.insert(END, "Alexa Category: " + str(response["Alexa category"]) + "\n")
                domainnewline()
            if 'Alexa domain info' in response:
                DomainReportOutput.insert(END, "Alexa Domain Info: " + str(response["Alexa domain info"]) + "\n")
                domainnewline()
            if 'last_https_certificate' in response:
                domainstars()
                DomainReportOutput.insert(END, "**************Last SSL Certificate Info*************" + "\n")
                domainstars()
                if 'size' in response["last_https_certificate"]:
                    DomainReportOutput.insert(END, "Size: " + str(response["last_https_certificate"]["size"]) + "\n")
                    domainnewline()
                if 'algorithm' in response["last_https_certificate"]["public_key"]:
                    DomainReportOutput.insert(END,
                                              "Public Key Format: " + str(response["last_https_certificate"]["public_key"]
                                                                          ["algorithm"]) + "\n")
                    domainnewline()
                if 'rsa' in response["last_https_certificate"]["public_key"]:
                    DomainReportOutput.insert(END, "Key Size: " + str(response["last_https_certificate"]["public_key"]
                                                                      ["rsa"]["key_size"]) + "\n")
                    domainnewline()
                    DomainReportOutput.insert(END, "Modulus: " + str(response["last_https_certificate"]["public_key"]
                                                                     ["rsa"]["modulus"]) + "\n")
                    domainnewline()
                    DomainReportOutput.insert(END, "Exponent: " + str(response["last_https_certificate"]["public_key"]
                                                                      ["rsa"]["exponent"]) + "\n")
                    domainnewline()
                if 'algorithm' in response["last_https_certificate"]["public_key"]:
                    DomainReportOutput.insert(END, "Algorithm: " + str(response["last_https_certificate"]["public_key"]
                                                                       ["algorithm"]) + "\n")
                    domainnewline()
                if 'thumbprint_sha256' in response["last_https_certificate"]:
                    DomainReportOutput.insert(END, "Sha256 Thumbprint: " + str(response["last_https_certificate"]
                                                                               ["thumbprint_sha256"]) + "\n")
                    domainnewline()
                if 'cert_signature' in response["last_https_certificate"]:
                    DomainReportOutput.insert(END, "Cert Signature Algorithm: " +
                                              str(response["last_https_certificate"]["cert_signature"]
                                                  ["signature_algorithm"]) + "\n")
                    domainnewline()
                    DomainReportOutput.insert(END, "Cert Signature: " + str(response["last_https_certificate"]
                                                                            ["cert_signature"]["signature"]) + "\n")
                    domainnewline()
                if 'validity' in response["last_https_certificate"]:
                    DomainReportOutput.insert(END, "Not Valid After: " + str(response["last_https_certificate"]
                                                                             ["validity"]["not_after"]) + "\n")
                    domainnewline()
                    DomainReportOutput.insert(END, "Not Valid Before: " + str(response["last_https_certificate"]
                                                                              ["validity"]["not_before"]) + "\n")
                    domainnewline()
                if 'version' in response["last_https_certificate"]:
                    DomainReportOutput.insert(END, "Version: " + str(response["last_https_certificate"]["version"]) + "\n")
                if 'extensions' in response["last_https_certificate"]:
                    for data in response["last_https_certificate"]["extensions"]["certificate_policies"]:
                        DomainReportOutput.insert(END, "Extensions: " + str(data) + "\n")
                        domainnewline()
                    for data in response["last_https_certificate"]["extensions"]["extended_key_usage"]:
                        DomainReportOutput.insert(END, "Extended Key Usage: " + str(data) + "\n")
                        domainnewline()
                    for data in response["last_https_certificate"]["extensions"]["subject_alternative_name"]:
                        DomainReportOutput.insert(END, "Subject Alternative Name: " + str(data) + "\n")
                        domainnewline()
                    if 'authority_key_identifier' in response["last_https_certificate"]["extensions"]:
                        DomainReportOutput.insert(END, "Key ID: " + str(response["last_https_certificate"]
                                                                        ["extensions"]['authority_key_identifier'][
                                                                            'keyid']) + "\n")
                        domainnewline()
                    if 'ca_information_access' in response["last_https_certificate"]["extensions"]:
                        DomainReportOutput.insert(END, "CA Issuers: " + str(response["last_https_certificate"]
                                                                            ["extensions"]['ca_information_access'][
                                                                                'CA Issuers']) + "\n")
                        DomainReportOutput.insert(END, "OCSP: " + str(response["last_https_certificate"]
                                                                      ["extensions"]['ca_information_access'][
                                                                          'OCSP']) + "\n")
                        domainnewline()
                    if 'extensions' in response["last_https_certificate"]:
                        for data in response["last_https_certificate"]["extensions"]["crl_distribution_points"]:
                            DomainReportOutput.insert(END, "CRL Distribution Point: " + str(data) + "\n")
                            domainnewline()
                    if 'extensions' in response["last_https_certificate"]:
                        for data in response["last_https_certificate"]["extensions"]["key_usage"]:
                            DomainReportOutput.insert(END, "key Usage: " + str(data) + "\n")
                            domainnewline()
                    if 'signature_algorithm' in response["last_https_certificate"]:
                        DomainReportOutput.insert(END, "Signature Algorithm: " + str(response["last_https_certificate"]
                                                                                     ['signature_algorithm']) + "\n")
                        domainnewline()
                    if 'serial_number' in response["last_https_certificate"]:
                        DomainReportOutput.insert(END, "Serial Number: " + str(response["last_https_certificate"]
                                                                               ['serial_number']) + "\n")
                        domainnewline()
                    if 'thumbprint' in response["last_https_certificate"]:
                        DomainReportOutput.insert(END, "Thumbprint: " + str(response["last_https_certificate"]
                                                                            ['thumbprint']) + "\n")
                        domainnewline()
                    if 'Issuer' in response["last_https_certificate"]:
                        for data in response["last_https_certificate"]["Issuer"]:
                            DomainReportOutput.insert(END, "Issuer: " + str(data) + "\n")
                            domainnewline()
                    if 'subject' in response["last_https_certificate"]:
                        for data in response["last_https_certificate"]["subject"]:
                            DomainReportOutput.insert(END, "Subject: " + str(data) + "\n")
                            domainnewline()
                domainnewline()
            if 'Webutation domain info' in response:
                domainstars()
                DomainReportOutput.insert(END, "****************Webutation Domain Info**************" + "\n")
                domainstars()
                DomainReportOutput.insert(END, "Safety Score: " + str(response["Webutation domain info"]
                                                                      ['Safety score']) + "\n")
                DomainReportOutput.insert(END, "Contains Adult Content: " + str(response["Webutation domain info"]
                                                                                ['Adult content']) + "\n")
                DomainReportOutput.insert(END, "Verdict: " + str(response["Webutation domain info"]
                                                                 ['Verdict']) + "\n")
                domainnewline()
            if 'WOT domain info' in response:
                domainstars()
                DomainReportOutput.insert(END, "*****************WOT Domain Info********************" + "\n")
                domainstars()
                DomainReportOutput.insert(END, "WOT Domain Info: " + str(response["WOT domain info"]) + "\n")
                domainnewline()
            if 'continent' in response:
                domainstars()
                DomainReportOutput.insert(END, "*********************Continent************************" + "\n")
                domainstars()
                DomainReportOutput.insert(END, "Continent: " + response["continent"] + "\n")
                domainnewline()
            if 'country' in response:
                domainstars()
                DomainReportOutput.insert(END, "*********************Country************************" + "\n")
                domainstars()
                DomainReportOutput.insert(END, "Country: " + response["country"] + "\n")
                domainnewline()
            if 'as_owner' in response:
                domainstars()
                DomainReportOutput.insert(END, "***********************Owner************************" + "\n")
                domainstars()
                DomainReportOutput.insert(END, "Owner: " + response["as_owner"] + "\n")
                domainnewline()
            domainthank()
        except:
            # logic check to determine if the apikey parameter has been left blank
            apikey = ''
            swtichmode2 = True
            while swtichmode2:
                if apikey == '' or apikey is None:
                    try:
                        apikey = easygui.enterbox("Please enter a valid VirusTotal API Key!",
                                                  "Your API key appears to be invalid! Invalid keys"
                                                  "will result in API errors!")
                        if apikey is None:
                            break
                            quitprocess()
                        makeapifile(apikey)
                    except:
                        messagebox.showinfo("API Key cannot be left blank!")
                elif apikey != '':
                    swtichmode2 = False


Button(Domain, width=57, text='Request Domain Report', command=lambda: domainreportrequest(getapikey())).pack()


# define function to maintain count and id of URL files
def makedomainfile():
    newcounter = 0
    if os.path.isfile('domaincounterFile.json'):
        with open('domaincounterFile.json') as data_file:
            data = json.load(data_file)
        newcounter = data["counter"] + 1
        data_file.close()
        with open('domaincounterFile.json', 'w') as fp:
            fp.write("{\"counter\": " + str(newcounter) + "}")
        fp.close()
    else:
        with open('domaincounterFile.json', 'w') as fp:
            fp.write("{\"counter\": 0}")
    # write file that will be used to iterate and maintain record of URL data
    with open('Domain report ' + str(newcounter), 'w') as fp:
        fp.write(DomainReportOutput.get(1.0, END))
    domainthank2()


# define function to retrieve stats from desired url report
def displaydomainstatsonly(apikey):
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    newdomain2 = NewDomainScan.get()
    params = {'apikey': apikey, 'domain': newdomain2}
    isempty = True
    if newdomain2 == '':
        while isempty:
            messagebox.showinfo("An Error Occurred: ", "A valid Domain must be entered to request a Domain report "
                                                       "Lookup! (Please check if the Domain is a valid Domain)")
            IPReportOutput.insert(END, "An Error Occurred: Domain not found! (Please check if the Domain is a valid)"
                                       "file)" + "\n")
            break
            isempty = False
            quitprocess()
    elif newdomain2 != '':
        try:
            response = requests.get(url, params=params).json()
            # ensure text field is empty
            DomainReportOutput.delete(1.0, END)
            # write to text field
            if str(response["response_code"]) != "1":
                DomainReportOutput.insert(END, "An Error Occurred: Domain not found! (Please check if the Domain "
                                               "is a valid Domain)" + "\n")
                domainstars()
            if 'verbose_msg' in response:
                DomainReportOutput.insert(END, "verbose_msg: " + str(response["verbose_msg"]) + "\n")
                domainnewline()
            if 'network' in response:
                domainstars()
                DomainReportOutput.insert(END, "***********************Network**********************" + "\n")
                domainstars()
                DomainReportOutput.insert(END, "Network: " + response["network"] + "\n")
                domainnewline()
            if 'undetected_downloaded_samples' in response:
                domainstars()
                DomainReportOutput.insert(END, "*********************Detections*********************" + "\n")
                domainstars()
                DomainReportOutput.insert(END, "These are Download samples which return 0 detections" + "\n")
                domainstars()
                for data in response['undetected_downloaded_samples']:
                    DomainReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    DomainReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    domainnewline()
                domainstars()
                DomainReportOutput.insert(END, "*These are Download samples which return detections*" + "\n")
                domainstars()
                domainnewline()
                for data in response['detected_downloaded_samples']:
                    DomainReportOutput.insert(END, "Detected: " + data["date"] + "\n")
                    DomainReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    DomainReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    domainnewline()
            if 'undetected_referrer_samples' in response:
                domainstars()
                DomainReportOutput.insert(END, "These are Referrer samples which return 0 detections" + "\n")
                domainstars()
                domainnewline()
                for data in response['undetected_referrer_samples']:
                    DomainReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    DomainReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    domainnewline()
                domainstars()
                DomainReportOutput.insert(END, "*These are Referrer samples which return detections*" + "\n")
                domainstars()
                domainnewline()
                for data in response['undetected_referrer_samples']:
                    DomainReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    DomainReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    domainnewline()
            if 'undetected_urls' in response:
                domainstars()
                DomainReportOutput.insert(END, "**These are related URLs which return 0 detections**" + "\n")
                domainstars()
                domainnewline()
                for data in response['undetected_urls']:
                    DomainReportOutput.insert(END, "URL: " + str([data][0][0]) + "\n")
                    DomainReportOutput.insert(END, "Detections: " + str([data][0][2]) + "\n")
                    DomainReportOutput.insert(END, "Total: " + str([data][0][3]) + "\n")
                    domainnewline()
                domainstars()
                DomainReportOutput.insert(END, "***These are related URLs which return detections***" + "\n")
                domainstars()
                domainnewline()
                for data in response['detected_urls']:
                    DomainReportOutput.insert(END, "URL: " + str(data['url']) + "\n")
                    DomainReportOutput.insert(END, "Detections: " + str(data['positives']) + "\n")
                    DomainReportOutput.insert(END, "Total: " + str(data['total']) + "\n")
                    domainnewline()
            if 'undetected_communicating_samples' in response:
                domainstars()
                DomainReportOutput.insert(END, "**These are Comms samples which return 0 detections*" + "\n")
                domainstars()
                domainnewline()
                for data in response['undetected_communicating_samples']:
                    DomainReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    DomainReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    domainnewline()
                domainstars()
                DomainReportOutput.insert(END, "**These are Comms samples which return detections***" + "\n")
                domainstars()
                domainnewline()
                for data in response['detected_communicating_samples']:
                    DomainReportOutput.insert(END, "Positive Detections: " + str(data["positives"]) + "\n")
                    DomainReportOutput.insert(END, "Total Engines Searched: " + str(data["total"]) + "\n")
                    domainnewline()
        except:
            # logic check to determine if the apikey parameter has been left blank
            apikey = ''
            swtichmode2 = True
            while swtichmode2:
                if apikey == '' or apikey is None:
                    try:
                        apikey = easygui.enterbox("Please enter a valid VirusTotal API Key!",
                                                  "Your API key appears to be invalid! Invalid keys"
                                                  "will result in API errors!")
                        if apikey is None:
                            break
                            quitprocess()
                        makeapifile(apikey)
                    except:
                        messagebox.showinfo("API Key cannot be left blank!")
                elif apikey != '':
                    swtichmode2 = False


Label(Domain, width=60, text='Please be aware, Domain reports are sourced internally from external sources',
      bg='gray').pack()
Label(Domain, width=60, text='VirusTotal cannot generate new Domain scan reports from users', bg='gray').pack()
Label(Domain, width=60, text='Users may use the mouse wheel', bg='gray').pack()
Label(Domain, width=60, text='arrow keys or', bg='gray').pack()
Label(Domain, width=60, text='page up/down buttons to navigate text fields', bg='gray').pack()
Label(Domain, width=60, text='Domain Report Output', bg='gray').pack()
DomainReportOutput = Text(Domain, width=60)
DomainReportOutput.pack(expand="yes")
Button(Domain, width=57, text='View Domain Report Stats', command=lambda: displaydomainstatsonly(getapikey())).pack()
Button(Domain, width=57, text='Generate Domain report text file', command=lambda: makedomainfile()).pack()
Button(Domain, width=57, text='Exit Program', command=lambda: quitprocess()).pack()

"""##################################################################################################################"""

# call the method to generate the main menu frame on intial loop through program
raise_frame(MainMenu)

# execute main program loop
root.mainloop()

# if no functions are called, exit program (this should never execute if all is working as intended)
exit(0)


