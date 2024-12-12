# Author : Nils Fischer
# Context: Migrate Sophos UTM Mail Protection to Proxmox Mail Gateway
# Description: This script will migrate the whitelist and blacklist from Sophos UTM to Proxmox Mail Gateway
# Version: 1.1
import os
import xml.etree.ElementTree as ET
import requests

# Configuration
pmgApiUrl = input("Enter the URL of your PMG API (https://pmg.example.com:8006): ")

# Please provide root@pam credentials
pmgApiUser = 'root@pam'
pmgApiPassword = input("Enter the password for root@pam: ")


# Please provide your self signed certificate, so ssl verification can be done
providedCertificate = input("Please provide your selfsigned certificate or leave empty if not use (SelfSigned.crt): ")
if providedCertificate == '':
    certificatePath = False
else:
    certificatePath = os.path.join(os.path.dirname(__file__), providedCertificate)

# Do not change
blacklistApi = pmgApiUrl + '/api2/json/quarantine/blacklist'
whitelistApi = pmgApiUrl + '/api2/json/quarantine/whitelist'
whoObjectsApi = pmgApiUrl + '/api2/json/config/ruledb/who/'


def main():
    # Ask the user if what he wants to import
    print("Please select what you want to import:")
    print("1. User Whitelist and Blacklist")
    print("2. Global Whitelist and Blacklist")
    print("3. Both")
    print("4. Custom Entry")
    
    choice = input("Enter your choice: ")

    if choice == '1':
        importUserLists()
    elif choice == '2':
        importGlobalLists()
    elif choice == '3':
        importUserLists()
        importGlobalLists()
    elif choice == '4':
        addSpecificEntry()
    else:
        print("Invalid choice")


def login():
    # Login
    loginApi = pmgApiUrl + '/api2/json/access/ticket'
    loginData = {
        'username': pmgApiUser,
        'password': pmgApiPassword
    }

    response = requests.post(loginApi, json=loginData, verify=certificatePath)

    ticket = response.json()['data']['ticket']
    csrf = response.json()['data']['CSRFPreventionToken']

    print("Logging in...")
    
    return ticket, csrf

def loadFile():
    xml_file = os.path.join(os.path.dirname(__file__), 'data.xml')

    if not os.path.exists(xml_file):
        print("ERROR: XML File not found! Did you rename the file?")
        return

    tree = ET.parse(xml_file)
    return tree.getroot()

def importXgUserLists():
    root = loadFile()

    data = root.find('objects')
    data = data.find('aaa')
    data = data.find('content')
    data = data.find('user')
    data = data.find('content')

    userLists = []

    for obj in data:
        tempWhitelist = []
        tempBlacklist = []
        user = obj.find('content')
        username = user.find('name').find('content').text
        mail = user.find('email_primary').find('content').text
        for i in user.find('sender_whitelist'):
            if i.tag == 'content':
                tempWhitelist.append(i.text)
                
        for i in user.find('sender_blacklist'):
            if i.tag == 'content':
                tempBlacklist.append(i.text)
            
        
        userLists.append({
            'username': username,
            'mail': mail,
            'whitelist': tempWhitelist,
            'blacklist': tempBlacklist
        })
        
    importUserLists(userLists)
def importUserLists(userLists):
    ticket, csrf = login()
    
    for user in userLists:
        if user['mail'] == None:
            print("Skipping user " + user['username'] + " because of missing mail address")
            continue

        for mail in user['whitelist']:
            whitelistData = {
                'address': mail,
                'pmail': user['mail']
            }
            response = requests.post(whitelistApi, json=whitelistData, verify=certificatePath, cookies={'PMGAuthCookie': ticket}, headers={'CSRFPreventionToken': csrf})
            if response.status_code == 200:
                print("Whitelist entry " + mail + " added for " + user['mail'])
            
        for mail in user['blacklist']:
            blacklistData = {
                'address': mail,
                'pmail': user['mail']
            }
            response = requests.post(blacklistApi, json=blacklistData, verify=certificatePath, cookies={'PMGAuthCookie': ticket}, headers={'CSRFPreventionToken': csrf})
            if response.status_code == 200:
                print("Blacklist entry " + mail + " added for " + user['mail'])
    
    print("User lists imported")



# Import global whitelist and blacklist
def importGlobalLists():
    ticket, csrf = login()

    root = loadFile()

    data = root.find('objects')
    data = data.find('smtp')
    data = data.find('content')
    data = data.find('profile')
    data = data.find('content')
    data = data.find('REF_SMTPGlobalProfile')
    data = data.find('content')
    data = data.find('sender_blacklist')
    
    print("")
    print("")
    print("Please type the id of the Who group you want to import the blacklist:")
    for i in loadWhoObjects():
        print(i['name'] + " - ID: " + str(i['id']))
    whoGroup = input("Enter the ID of the Who Group: ")
    
    for obj in data:
        if obj.tag != 'content':
            continue
        
        # Check if mail starts with *@
        if obj.text.startswith('*@'):
            domain = obj.text[2:]
            blacklistData = {
                'domain': domain,
            }
            response = requests.post(whoObjectsApi + whoGroup + '/domain', json=blacklistData, verify=certificatePath, cookies={'PMGAuthCookie': ticket}, headers={'CSRFPreventionToken': csrf})
            if response.status_code == 200:
                print("Blacklist entry " + domain + " added")
        else:
            email = obj.text
            blacklistData = {
                'email': email,
            }
            response = requests.post(whoObjectsApi + whoGroup + '/email', json=blacklistData, verify=certificatePath, cookies={'PMGAuthCookie': ticket}, headers={'CSRFPreventionToken': csrf})
            if response.status_code == 200: 
                print("Blacklist entry " + email + " added")


    print("Blacklist imported")
    
    print("")
    print("")
    print("Please type the id of the Who group you want to import the whitelist:")
    for i in loadWhoObjects():
        print(i['name'] + " - ID: " + str(i['id']))
    whoGroup = input("Enter the ID of the Who Group: ")
    
    data = root.find('objects')
    data = data.find('smtp')
    data = data.find('content')
    data = data.find('exception')
    data = data.find('content')
    data = data.find('REF_SmtExcWhitelist')
    data = data.find('content')
    data = data.find('senders')
    
    for obj in data:
        if obj.tag != 'content':
            continue
        
        if obj.text.startswith('*@'):
            domain = obj.text[2:]
            whitelistData = {
                'domain': domain,
            }
            response = requests.post(whoObjectsApi + whoGroup + '/domain', json=whitelistData, verify=certificatePath, cookies={'PMGAuthCookie': ticket}, headers={'CSRFPreventionToken': csrf})
            if response.status_code == 200:
                print("Whitelist entry " + domain + " added")
        else:
            email = obj.text
            whitelistData = {
                'email': email,
            }
            response = requests.post(whoObjectsApi + whoGroup + '/email', json=whitelistData, verify=certificatePath, cookies={'PMGAuthCookie': ticket}, headers={'CSRFPreventionToken': csrf})
            if response.status_code == 200:
                print("Whitelist entry " + email + " added")

    print("Whitelist imported")

        
def loadWhoObjects():
    ticket, csrf = login()
    api = pmgApiUrl + '/api2/json/config/ruledb/who/'
    response = requests.get(api, verify=certificatePath, cookies={'PMGAuthCookie': ticket}, headers={'CSRFPreventionToken': csrf})
    print("Loading Who Objects...")
    return response.json()['data']

def addSpecificEntry():
    exit = True
    
    email = input("Enter the email address from user: ")
    type = input("Enter the type (whitelist or blacklist): ")
    
    while(exit):
        mail = input("Enter the mail address/domain you want to block/whitelist (*@domain.com, abc@domain.com): ")
        
        userLists = [
            {
                'username': 'custom.entry',
                'mail': email,
                'whitelist': [mail] if type == 'whitelist' else [],
                'blacklist': [mail] if type == 'blacklist' else []
            },
        ]
        
        importUserLists(userLists)
        
        exit = input("Do you want to add another entry? (y/n): ")
        if exit == 'n':
            exit = False
        
    
    # Go to main menu
    main()

main()