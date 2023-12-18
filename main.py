import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinterdnd2 import TkinterDnD, DND_FILES
import requests
import os
import time
import threading

class VirusTotalScannerApp:
    # Init function
    def __init__(self, root, apikey):
        self.root = root
        # Set title
        self.root.title("VirusTotal Scanner")

        self.file_count = 0

        self.apikey = apikey

        # Set instruction
        self.label = ttk.Label(root, text="Select a folder or a file to scan:")
        self.label.pack(pady=10)

        # Set a blank area that the path will be there after choice
        self.folder_var = tk.StringVar()
        self.folder_entry = ttk.Entry(root, textvariable=self.folder_var, state="readonly")
        self.folder_entry.pack(pady=10, ipadx=100)

        # Set button to browse folder
        self.browse_folder_button = ttk.Button(root, text="Browse Folder", command=self.BrowseFolder)
        self.browse_folder_button.pack(pady=10)
        
        # Set button to browse a single file
        self.browse_file_button = ttk.Button(root, text="Browse File", command=self.BrowseFile)
        self.browse_file_button.pack(pady=10)

        # Set button to start the scan
        self.start_button = ttk.Button(root, text="Start Scan", command=self.StartScan)
        self.start_button.pack(pady=10)

        # Write a keys for each color
        self.status_keys = ttk.Label(root, text="Green - Safe , Yellow - Not Checked , Red - Infected")
        self.status_keys.pack(pady=10)

        # Set lable
        self.status_label = ttk.Label(root, text="Scan Status:")
        self.status_label.pack(pady=10)

        # Set area for stuts for every file
        self.text_status = tk.Text(root, height=20, width=100, state="disabled", background="black")
        self.text_status.pack(pady=10)
        self.text_status.tag_configure("def", foreground="white")
        self.text_status.tag_configure("safe", foreground="green")
        self.text_status.tag_configure("notChecked", foreground="yellow")
        self.text_status.tag_configure("infected", foreground="red")

        # Set quit button
        self.quit_button = ttk.Button(root, text="Quit", command=root.quit)
        self.quit_button.pack(pady=10)

        # Update the path area if the user choose a file or folder
        self.root.drop_target_register(DND_FILES)
        self.root.dnd_bind('<<Drop>>', self.UpdateFileOrFolderEntry)

        self.all_safe = True

    def BrowseFolder(self):
        # The function ask directory of the folder and set it as path
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.folder_var.set(folder_path)

    def BrowseFile(self):
        # The function ask directory of the file and set it as path
        file_path = filedialog.askopenfilename()
        if file_path:
            self.folder_var.set(file_path)

    def UpdateFileOrFolderEntry(self, event):
        # The function update the path if the user define path
        file_or_folder_path = event.data
        self.folder_var.set(file_or_folder_path)

    def StartScan(self):
        # The function check if the file or the folder still exists, if true create thread to scan the file or the folder
        file_or_folder_path = self.folder_var.get()
        if os.path.exists(file_or_folder_path):
            self.text_status.config(state=tk.NORMAL)
            self.text_status.delete(1.0, tk.END)
            self.text_status.insert(tk.END, "Scanning...\n\n", "def")
            self.text_status.config(state=tk.DISABLED)

            thread = threading.Thread(target=self.ScanFileOrFolder, args=(file_or_folder_path,))
            thread.start()
        else:
            messagebox.showwarning("Invalid Path", "Please select a valid file or folder for scanning.")

    def ScanFileOrFolder(self, file_or_folder_path):
        # The function get path and check if the user entered file or folder and do the scan for each, check errors like PermissionError and 
        # show an appropriate message and finally check if the scan has finished
        try:
            if os.path.isfile(file_or_folder_path):
                result = self.ScanFile(file_or_folder_path)
                self.UpdateScanStatus(f"Scanning : {file_or_folder_path}", result)
            elif os.path.isdir(file_or_folder_path):
                self.ScanFolder(file_or_folder_path)
        except PermissionError:
            result = "notChecked"
            self.UpdateScanStatus(f"Scanning : {file_or_folder_path} , Access is denied", result)
        finally:
            self.FinishScan()

    def ScanFolder(self, folder_path):
        # The function get path of folder and check every file in this folder in recursive way and checking errors
        try:
            for item in os.listdir(folder_path):
                item_path = os.path.join(folder_path, item)
                if os.path.isfile(item_path):
                    result = self.ScanFile(item_path)
                    self.UpdateScanStatus(f"Scanning : {item_path}", result)
                    self.file_count += 1
                    if self.file_count % 2 == 0:
                        time.sleep(60)
                elif os.path.isdir(item_path):
                    self.ScanFolder(item_path)
        except PermissionError:
            result = "notChecked"
            self.UpdateScanStatus(f"Scanning : {folder_path} , Access is denied", result)

    def ScanFile(self, file_path):
        # The function get path of file and check the file with VirusTotal API, check errors and return an appropriate message
        try:
            resource = self.GetResponseScan(file_path).json()['resource']
            response_rep = self.GetResponseReport(resource)
            if not response_rep.json()['positives'] == 0:
                self.all_safe = False
                return "infected"
            else:
                return "safe"
        except Exception:
            return "notChecked"

    def GetResponseScan(self, file_path):
        # The function get file path and return the response scan of VirusTotal API
        url_scan = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params_scan = {'apikey': self.apikey}
        files_scan = {'file': (file_path, open(file_path, 'rb'))}
        response_scan = requests.post(url_scan, files=files_scan, params=params_scan)
        return response_scan

    def GetResponseReport(self, resource):
        # The function get the resource of the response scan and return the response report of VirusTotal API
        url_rep = 'https://www.virustotal.com/vtapi/v2/file/report'
        params_rep = {'apikey': self.apikey, 'resource': resource}
        response_rep = requests.get(url_rep, params=params_rep)
        return response_rep

    def UpdateScanStatus(self, result, tag):
        # The function get result and tag that the result is the message and the tag is the color of the message and show it to the user
        self.text_status.config(state=tk.NORMAL)
        self.text_status.insert(tk.END, result + "\n\n", tag)
        self.text_status.config(state=tk.DISABLED)
        self.text_status.see(tk.END)

    def FinishScan(self):
        # The function show the user final message, if the folder or the file are infected or not
        self.text_status.config(state=tk.NORMAL)
        if self.all_safe:
            self.text_status.insert(tk.END, "Scan completed. All files are clean!\n\n", "safe")
        else:
            self.text_status.insert(tk.END, "Scan completed. Some files are infected.\n\n", "infected")
        self.text_status.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    apikey = '<APIKEY>'
    app = VirusTotalScannerApp(root, apikey)
    root.mainloop()
