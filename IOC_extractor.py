# Step 1 importing module and loading the extractor 
import re 
print ("IOC extractor has been loaded sucessfully .............") 
# Step 2 - IP address Pattern
ip_pattern = re.compile(r'\b((\d{1,3}\.){3}\d{1,3})\b')

#text containing IOCs 
test_test = """ Malicious activity was observed from 192.168.1.1 and 45.33.32.156 attempting to connect to 10.0.0.1 .
The domains mailicious-site.com and sub.badactor.xyz were used as command and control infrastructure. The payload was downloaded from https://malicious-site.com/payload/file.exe
and http://sub.badactor.xyz/download?id=123 was used for data exfiltration.No activity from 999.999.999.999."""

#search for IP address in test_test
found_ips = ip_pattern.findall(test_test)

#Display results 
print("IP adresses found:")
for ip in found_ips:
    print(ip[0])

domain_pattern = re.compile(r'(?<![:/])\b((?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|mil|xyz|io|co|uk|de|fr|ru|cn|jp))\b')
found_domains=domain_pattern.findall(test_test)
print("Domains Found:")
for domain in found_domains:
    print(domain)

#url_pattern
url_pattern = re.compile(r'(https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}(?:/[^\s]*)?)')
#search for urls
found_urls=url_pattern.findall(test_test)
print("\n Found URLs:")
for url in found_urls:
    print(url)