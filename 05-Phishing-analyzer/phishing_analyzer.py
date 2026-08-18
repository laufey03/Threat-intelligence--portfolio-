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

 
