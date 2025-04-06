# VM-google.exe-Threat-Hunt



---


---

### **Threat Event:** Unauthorized Chrome Extension

---

### **Example Scenario:**

📌 **Reason for the Threat Hunt:**  
**Unusual System Behavior Reported**  
An employee reported that their browser (Google Chrome) is behaving strangely—opening random tabs, redirecting search results, and running slower than normal. Management suspects a malicious Chrome extension may have been installed and asks for a threat hunt across systems.

---

### **🧠 Tables Used to Detect Google Chrome IoCs:**

| Parameter             | Description                                                            |
|-----------------------|------------------------------------------------------------------------|
| DeviceFileEvents      | Detects CRX download, creation of browser-data-export.txt              |
| DeviceProcessEvents   | Detects Chrome launching and handling extensions                       |
| DeviceNetworkEvents   | Detects unusual outbound connections possibly initiated by Chrome       |

---

### **Steps Taken**

**1. Searched the DeviceProcessEvents Table – Chrome Launched with Suspicious Arguments**  
🕒 **Timestamp:** April 5, 2025 – 10:18:05 PM to 10:18:17 PM  
I began my investigation by examining process activity on the device **"vmgoogle-corey"**. I identified multiple instances of `chrome.exe` being launched by the user **"labuser"** with suspicious command-line arguments such as `--extension-process`, `--utility-sub-type=chrome.mojom.ProcessorMetrics`, and `--disable-gpu-compositing`. These flags are often linked to browser automation, side-loaded extensions, and exploit frameworks, which raised initial red flags suggesting potential browser manipulation or script execution.

![2 KQL Chrome launched with any arguments device process events](https://github.com/user-attachments/assets/5c88b0a6-e40a-4b5e-a19a-208066265986)


---

**2. Searched the DeviceFileEvents Table – Tampermonkey .CRX File Downloaded**  
🕒 **Timestamp:** April 5, 2025 – 10:30:29 PM  
Next, I pivoted to file download activity and discovered that the user **"labuser"** downloaded a `.crx` file named **`dhdgffkkebhmkfjojejmpbldmpobfkfo_10721.crx`**. The file was written to Chrome’s Webstore Downloads folder, confirming it was retrieved via the browser process (`chrome.exe`). The filename matches the Tampermonkey extension, and its download outside of Chrome’s official extension store suggests a **side-loaded extension**, which is commonly used for injecting malicious userscripts or browser-based data theft tools.

![1 KQL CRX FILE DOWNLOAD device file events](https://github.com/user-attachments/assets/9afe16a0-a608-42de-9e09-7c2d77c5e872)

---

**3. Searched the DeviceNetworkEvents Table – External Connections Initiated by Chrome**  
🕒 **Timestamp:** April 5, 2025 – 10:35:02 PM to 10:35:11 PM  
Shortly after the `.crx` download, I found that `chrome.exe`, still under the **"labuser"** account, established multiple outbound HTTPS connections to several external domains. These included:

- **tampermonkey.net** (extension beaconing)  
- **x.bidswitch.net** (suspicious adtech domain often abused for C2)  
- **temu.com**, **reddit.com**, and **youtube-nocookie.com** (likely used to blend in with normal web traffic)

This behavior strongly indicated that the **side-loaded Tampermonkey extension had triggered automated scripts**, potentially used to **exfiltrate browser data**, **gather system info**, or **connect to attacker infrastructure**, while hiding among trusted traffic.

![4 Chrome network activity (look for unusual remote IPs or domains) tampermonkey](https://github.com/user-attachments/assets/6c2820bf-4156-4949-b6b9-9821ad62f022)

---

**4. Searched the DeviceFileEvents Table – Suspicious Export File Created and Modified**  
🕒 **Timestamp:** April 5, 2025 – 10:37:22 PM to 10:38:16 PM  
I then observed the creation and modification of a file named **`browser-data-export.txt.txt`**, along with a `.lnk` shortcut version in the **Recent Files** folder. This file was created, modified twice, and renamed within one minute—indicating possible **manual data staging** or **preparation for browser data exfiltration**. The folder path showed it was located on the user’s Desktop, and the shortcut suggests the file had been interacted with, either by a user or script.

![3  Suspicious text file created and deleted](https://github.com/user-attachments/assets/009e86b0-e187-4262-b327-59ed99665985)

---

**5. Searched the DeviceFileEvents Table – Malicious Script Reference Found**  
🕒 **Timestamp:** April 6, 2025 – 12:27:49 AM  
Finally, I discovered a newly created shortcut file titled **`harmful scripts tampermonkey.lnk`** located in the user’s **Recent Items** directory. This strongly suggests that a **Tampermonkey userscript—potentially harmful—was launched or interacted with** shortly after the previous suspicious activity. The naming convention, along with its placement, points to either an **attacker leaving artifacts** behind or a **simulation of script-based post-exploitation activity**.

![5  Suspicious text file created and deleted](https://github.com/user-attachments/assets/d8b24662-9162-46dc-9dec-262f333440de)

---

### **Chronological Event Timeline**

**1. Process Execution – Chrome Launched with Suspicious Arguments**  
**Timestamp:** April 5, 2025 – 10:18:05 PM to 10:18:17 PM  
**Event:** The user **"labuser"** launched `chrome.exe` multiple times with suspicious command-line arguments.  
**Action:** Process creation detected.  
**Command-Line Arguments:**  
- `--extension-process`  
- `--utility-sub-type=chrome.mojom.ProcessorMetrics`  
- `--disable-gpu-compositing`  
**Device:** vmgoogle-corey

---

**2. File Download – Tampermonkey .CRX Extension File**  
**Timestamp:** April 5, 2025 – 10:30:29 PM  
**Event:** The user **"labuser"** downloaded a Chrome extension package file named **`dhdgffkkebhmkfjojejmpbldmpobfkfo_10721.crx`**, associated with Tampermonkey.  
**Action:** File download detected.  
**File Path:**  
`C:\Users\labuser\AppData\Local\Google\Chrome\User Data\Webstore Downloads\dhdgffkkebhmkfjojejmpbldmpobfkfo_10721.crx`  
**Process:** chrome.exe  
**Device:** vmgoogle-corey

---

**3. Network Connections – External Traffic Initiated by Chrome**  
**Timestamp:** April 5, 2025 – 10:35:02 PM to 10:35:11 PM  
**Event:** Following the `.crx` download, `chrome.exe` initiated several external HTTPS connections.  
**Action:** External network connections detected.  
**Remote Domains:**  
- tampermonkey.net (extension beaconing)  
- x.bidswitch.net (suspicious adtech/C2 infrastructure)  
- temu.com, reddit.com, youtube-nocookie.com (used to blend into normal traffic)  
**Protocol:** TCPv4 over port 443  
**Device:** vmgoogle-corey

---

**4. File Creation & Modification – Suspicious Export File**  
**Timestamp:** April 5, 2025 – 10:37:22 PM to 10:38:16 PM  
**Event:** The user **"labuser"** created, modified, and renamed a suspicious file named **`browser-data-export.txt.txt`** on the Desktop, along with a `.lnk` shortcut version.  
**Action:** File creation, modification, and rename detected.  
**File Paths:**  
- `C:\Users\labuser\Desktop\browser-data-export.txt.txt`  
- `C:\Users\labuser\AppData\Roaming\Microsoft\Windows\Recent\browser-data-export.txt.lnk`  
**Device:** vmgoogle-corey

---

**5. File Creation – Malicious Tampermonkey Script Reference**  
**Timestamp:** April 6, 2025 – 12:27:49 AM  
**Event:** A shortcut file named **`harmful scripts tampermonkey.lnk`** was created in the **Recent Items** folder, indicating interaction with a suspicious or malicious Tampermonkey userscript.  
**Action:** File creation detected.  
**File Path:**  
`C:\Users\labuser\AppData\Roaming\Microsoft\Windows\Recent\harmful scripts tampermonkey.lnk`  
**Device:** vmgoogle-corey

---

### **Summary**

On **April 5, 2025**, I investigated suspicious activity on **device "vmgoogle-corey"** tied to the user **"labuser"**. The user launched **Chrome with suspicious command-line arguments**, then downloaded a **Tampermonkey `.crx` extension** outside the official Chrome Web Store—indicating a likely **side-loaded, unauthorized extension**.

Minutes later, Chrome initiated **outbound connections** to domains including **tampermonkey.net**, **x.bidswitch.net**, and others commonly used to **blend malicious traffic into normal web activity**. This suggests the extension triggered **automated scripts**, potentially used for **data exfiltration or system reconnaissance**.

Shortly after, a file named **`browser-data-export.txt.txt`** was created and modified, followed by the appearance of a shortcut labeled **`harmful scripts tampermonkey.lnk`**, pointing to a **malicious userscript** in use—likely part of a **script-based post-exploitation technique**.

---

### **Response Taken**

**Tampermonkey-based malicious activity was confirmed on endpoint `vmgoogle-corey` by user `labuser`. The device was isolated and the user's direct manager was notified.**

---

