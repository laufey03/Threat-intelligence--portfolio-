import re
import email 

print ("\n Phishing Email Header analyzer loaded sucessfully.........")
print("\n Paste the Raw Email header below ....")
print("\n Press enter twice when done :")

lines = []
while True:
    line = input()
    if line == "":
        break
    lines.append(line)
raw_header = "\n".join(lines)

msg= email.message_from_string(raw_header)

from_address = msg.get('From', 'Not found')
reply_to = msg.get('Reply-To', 'Not found')
return_path = msg.get('Return-Path', 'Not found')
subject = msg.get('Subject', 'Not found')
date = msg.get('Date', 'Not found')

auth_results = ""
for line in lines:
    if 'Authentication-Results' in line or "spf=" in line.lower() or "dkim=" in line.lower() or "dmarc=" in line.lower():
        auth_results += ''

spf_match = re.search(r'spf=(\w+)', auth_results.lower())
spf_result = spf_match.group(1) if spf_match else 'Not found'

dkim_match = re.search(r'dkim=(\w+)', auth_results.lower())
dkim_result = dkim_match.group(1) if dkim_match else 'Not found'

dmarc_match = re.search(r'dmarc=(\w+)', auth_results.lower())
dmarc_result = dmarc_match.group(1) if dmarc_match else 'Not found'


print("\n ==============================================================================================================")
print("\n                                     PHISHING EMAIL ANALYSIS RESULTS                                           ")
print("\n ==============================================================================================================")
print(f"\n        Subject         :  {subject}")
print(f"\n        Date            :  {date}")
print(f"\n        From            :  {from_address}")
print(f"\n        Reply-To        :  {reply_to}")
print(f"\n        Return-Path     :  {return_path}")

print(f"\n                               --------AUTHENTICATION RESULTS-------------                                     ")
print(f"\n         SPF             : {spf_result}")
print(f"\n         DKIM            : {dkim_result}")
print(f"\n         DMARC           : {dmarc_result}")

print("\n                               ---------SUSPICIOUS INDICATORS---------------                                     ")

if spf_result == "fail":
    print ("\n   !  SPF - failed  - Sender is not authorised to send mail from this domain  ")

if dkim_result == "fail":
    print("\n    ! DKIM - failed - E-mail might be tampered")
if dmarc_result == "fail":
    print ("\n   ! DMARC - failed - Domain Authentication failed ")

if reply_to != "Not found" and reply_to != from_address:
    print(f"\n ! Reply-To Mismatch From address : {from_address} but Reply-To : {reply_to} ")

if spf_result != "fail" and dkim_result != "fail" and dmarc_result != "fail" and (reply_to == "Not found" or reply_to == from_address):
    print("   [+] NO SUSPICIOUS INDICATORS DETECTED ........")

print("\n ===============================================================================================================")