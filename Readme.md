# Migrate your Mail White and Blacklists from Sophos UTM to Proxmox Mail Gateway

## Export XML file
1. Go to Sophos UTM Admin Portal
2. Go to Support
3. Go to Printable Configuration
4. Generate Report now
5. Scroll down and click on "in Confd format"
6. Right click page and save to Project Folder
7. Rename to "data.xml"

## Install python and requirements
```python -m pip install requirements.txt```

## Configure the script
1. Open main.py
2. Change pmgApiUrl to your PMG Instance
3. Edit Username and Password

## Optional: Add self signed root certificate
1. Put your Root Certificate into the project folder
2. Rename it or change the certificatePath in main.py

# Run script
```python3 main.py```