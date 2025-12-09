# **🛡️ Phishing Email Detective**  

*A simple, powerful tool to detect phishing emails instantly*

---

## **🎯 What It Does**

This tool analyzes email files (.eml format) and tells you:
- ✅ **If an email is safe** (Green score)
- ⚠️ **If it's suspicious** (Yellow score)  
- 🚨 **If it's likely phishing** (Red score)

**Get detailed reports with explanations of why an email is risky!**

---

## **🚀 Get Started in 2 Minutes**

### **Step 1: Download & Setup**
1. **Download** all files to a folder (like `C:\Phishing-detector`)
2. **Open Command Prompt** (Windows + R, type `cmd`, press Enter)

### **Step 2: Install Requirements**
In Command Prompt, type:
```cmd
pip install tldextract validators
```
Press **Enter**

### **Step 3: Run the Tool**
```cmd
cd C:\Phishing-detector
python detector.py
```
*(Replace `C:\Phishing-detector` with your actual folder path)*

---

## **📧 How to Use - Easy 3 Steps**

### **Step 1: Save Your Email**
- From **Gmail**: Open email → Click 3 dots → "Download message"
- From **Outlook**: Right-click email → "Save As" → Choose ".eml"
- Save the file in the **same folder** as `detector.py`

### **Step 2: Run the Analysis**
1. Open terminal in the folder
2. Type: `python detector.py`
3. When asked, type your email filename (e.g., `suspicious-email.eml`)

### **Step 3: Get Your Results**
- **Immediate risk score** (0-100)
- **Clear color-coded warning**
- **HTML report** with full details
- **Action recommendations**

---

## **📊 Understanding Your Results**

### **Risk Score Guide:**
| Score | Risk Level | What It Means | What to Do |
|-------|------------|---------------|------------|
| **0-39** | **🟢 LOW** | Email looks safe | Proceed normally |
| **40-69** | **🟡 MEDIUM** | Some suspicious signs | Verify sender, be careful |
| **70-100** | **🔴 HIGH** | Likely phishing | DELETE immediately! |

---

## **🎯 Quick Test - Try It Now!**

### **Create a Test Email:**
1. Open **Notepad**
2. Copy this text:
```
From: security@fake-bank.xyz
Subject: URGENT: Account Locked!

Click now: https://bank-security-update.xyz/reset
Your password needs immediate verification!
```
3. Save as `test.phish.eml` in your detector folder

### **Run the Test:**
```cmd
python detector.py
```
When asked: `Enter path to email file (.eml):` type `test.phish.eml`

**You'll see:** 🚨 **HIGH RISK** with detailed explanation!

---

## **✨ Key Features**

### **🔍 Detection Capabilities:**
- **100+ phishing keywords** monitored
- **URL safety analysis** (catches suspicious links)
- **Email authentication checks** (SPF/DKIM/DMARC)
- **Attachment warnings**
- **Sender reputation analysis**

### **📈 Professional Reports:**
- **Color-coded risk levels**
- **Keyword breakdown** (shows what was found)
- **URL analysis** (why links are suspicious)
- **Score calculation** (how the score was determined)
- **Actionable recommendations**

### **🔒 Privacy First:**
- **100% offline** - No internet needed
- **No data collection** - Everything stays on your computer
- **Safe for confidential emails**
- **No registration required**

---

## **🖥️ Two Ways to Use**

### **Option 1: Using VS Code (Easiest)**
```bash
1. Open VS Code
2. Click File → Open Folder → Select your folder
3. Press Ctrl + ` to open terminal
4. Type: python detector.py
5. Enter email filename
```

### **Option 2: Using Command Prompt**
```bash
1. Open Command Prompt (cmd)
2. Type: cd C:\YourFolderPath
3. Type: python detector.py
4. Enter email filename
```

---


## **⚡ Quick Command Reference**

```bash
# Basic analysis
python detector.py

# When asked for file:
suspicious-email.eml

# Want HTML report?
Generate HTML report? (y/n): y

# Want to open in browser?
Open report in browser? (y/n): y

# View usage statistics
# Run tool, choose "2. View Analytics" from menu
```

---

## **🆘 Troubleshooting**

### **Common Issues & Fixes:**

| Problem | Solution |
|---------|----------|
| **"Module not found"** | Run: `pip install tldextract validators` |
| **"File not found"** | Make sure email is in same folder as detector.py |
| **"Python not recognized"** | Reinstall Python, check "Add to PATH" |
| **Can't open .eml files** | Save emails as .eml format (not .msg or .txt) |
| **HTML report won't open** | Check `reports/` folder, open manually |

### **Still Having Trouble?**
1. **Check Python version**: Type `python --version` (should show Python 3.x)
2. **Verify location**: Type `dir` to see if `detector.py` is listed
3. **Test with sample**: Use the test email above first

---

## **🎓 Learn While You Detect**

### **What Makes an Email Suspicious:**
- **Urgent language** ("ACT NOW!", "Immediately")
- **Requests for passwords** or personal info
- **Suspicious links** (strange domains like .xyz, .top)
- **Poor grammar/spelling**
- **Generic greetings** ("Dear Customer" instead of your name)

### **Tool as a Learning Aid:**
- See exactly **which keywords** triggered alerts
- Understand **why URLs are suspicious**
- Learn about **email authentication**
- Get **visual feedback** on risk factors

---

## **📊 Analytics Dashboard**

The tool tracks (locally on your computer):
- **Total analyses performed**
- **Risk distribution** (high/medium/low counts)
- **Daily usage patterns**
- **Recent scans**

**To view analytics:** Run the tool and choose "View Analytics" from the menu

---

## **🔧 Advanced Features**

### **Batch Processing:**
Scan multiple emails at once by placing them all in the folder and running the tool for each.

### **Custom Keyword List:**
Add your own suspicious keywords by editing the `PHISHING_KEYWORDS` list in `detector.py`.

### **Report Export:**
All HTML reports are saved in the `reports/` folder for later review or sharing.

---

## **⚠️ Important Notes**

### **Limitations:**
- Not 100% accurate (no tool is)
- New phishing techniques may evade detection
- Legitimate security emails may trigger false alarms

### **Best Practices:**
1. **Use as a guide**, not absolute truth
2. **When in doubt, verify** through official channels
3. **Never click links** in high-risk emails
4. **Report phishing** to your email provider
5. **Keep the tool updated** with new keywords

---

## **📞 Need Help?**

### **Quick Checklist:**
- [ ] Python installed? (`python --version`)
- [ ] Packages installed? (`pip install tldextract validators`)
- [ ] Files in same folder? (`dir` shows detector.py)
- [ ] Email saved as .eml format?
- [ ] Typing correct command? (`python detector.py`)

### **First-Time Success Path:**
```bash
1. Download all files to C:\Phishing-detector
2. Open Command Prompt
3. Type: cd C:\Phishing-detector
4. Type: pip install tldextract validators
5. Type: python detector.py
6. Type: test.phish.eml (use test email above)
7. Celebrate! 🎉
```

---

## **📝 License & Credits**

- **Free for personal and educational use**
- **No warranties** - Use at your own risk
- **Community-maintained** - Contributions welcome
- **Privacy-focused** - No tracking or data collection

---

## **🌟 Why Choose This Tool?**

| Feature | Benefit |
|---------|---------|
| **Easy to use** | No technical skills needed |
| **Fast analysis** | Results in seconds |
| **Detailed reports** | Understand WHY email is risky |
| **100% offline** | Complete privacy |
| **Educational** | Learn to spot phishing yourself |
| **Free forever** | No cost, no limits |

---

## **🚀 Ready to Start?**

### **Complete Beginner's Path:**
1. **Download** the tool files to a folder
2. **Create** the test email (copy from above)
3. **Run** the commands below:
   ```bash
   pip install tldextract validators
   python detector.py
   test.phish.eml
   ```
4. **See** your first phishing detection!

### **Need Visual Help?**
Check the `reports/` folder after analysis - beautiful HTML reports show everything visually!

---

**Remember:** This tool helps you make better decisions about email safety. Stay vigilant, think before you click, and when in doubt, delete suspicious emails!

---

**Happy phishing hunting! 🔍🛡️**  

*Found a phishing email? Add its keywords to help improve detection for everyone!*
