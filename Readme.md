# Migrate your Mail White and Blacklists from Sophos UTM to Proxmox Mail Gateway
## And or add custom entries for mail address manually

## Export XML file
1. Go to Sophos UTM Admin Portal
2. Go to Support
3. Go to Printable Configuration
4. Generate Report now
5. Scroll down and click on "in Confd format"
6. Right click page and save to Project Folder
7. Rename to "data.xml"

## Install python and requirements
```python3 -m pip install -r requirements.txt```

## Start script
Linux: ```python3 main.py```
Windows: Execute Start.bat

## Optional: Add self signed root certificate
1. Put your Root Certificate into the project folder
2. Provide the file name if script is asking for