# Step 1 importing module and loading the extractor 
import re 
print ("IOC extractor has been loaded sucessfully .............") 
# Step 2 - IP address Pattern
ip_pattern = re.compile(r'\b((\d{1,3}\.){3}\d{1,3})\b')

#text containing IOCs 
test_test = """ Malicious activity was observed from 192.168.1.1 and 45.33.32.156 attempting to connect to 10.0.0.1 .
no activity from 999.999.999.999."""

#search for IP address in test_test
found_ips = ip_pattern.findall(test_test)

#Display results 
print("IP adresses found:")
for ip in found_ips:
    print(ip[0])