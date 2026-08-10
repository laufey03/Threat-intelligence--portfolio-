# Step 1 importing module and loading the extractor 
import re 

#text containing IOCs code testing 
#test_test = """ Malicious activity was observed from 192.168.1.1 and 45.33.32.156 attempting to connect to 10.0.0.1 .
#The domains mailicious-site.com and sub.badactor.xyz were used as command and control infrastructure. The payload was downloaded from https://malicious-site.com/payload/file.exe
#and http://sub.badactor.xyz/download?id=123 was used for data exfiltration.MD5 hash: d41d8cd98f00b204e9800998ecf8427e
#SHA1 hash: da39a3ee5e6b4b0d3255bfef95601890afd80709
#SHA256 hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
#SHA512 hash: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
#No activity from 999.999.999.999."""

print ("IOC extractor has been loaded sucessfully .............") 

# Getting input from the analyst

print("\nInput your threat intel data:")
print("Press enter twice when done.......\n")
lines = []
while True:
    line = input()
    if line == "":
       break
    lines.append(line)
text = "\n".join(lines)

print("\n =======================================================================================================")
print("\n                                     IOC EXTRACTION RESULTS                  ")
print("\n =======================================================================================================")

# Step 2 - IP address Pattern
ip_pattern = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')

#search for IP address in test_test
found_ips = ip_pattern.findall(text)

#Display results 
print(f"\n   [+] IP adresses found: {len(found_ips)}")
for ip in found_ips:
    print(f"   ->  {ip}")

#domain_pattern

domain_pattern = re.compile(r'(?<![:/])\b((?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|mil|xyz|io|co|uk|de|fr|ru|cn|jp))\b')
found_domains=domain_pattern.findall(text)
print(f"\n   [+] Domains Found:{len(found_domains)}")
for domain in found_domains:
    print(f"   ->  {domain}")

#url_pattern
url_pattern = re.compile(r'(https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}(?:/[^\s]*)?)')
#search for urls
found_urls=url_pattern.findall(text)
print(f"\n   [+] Found URLs:{len(found_urls)}")
for url in found_urls:
    print(f"   -> {url}")

#hash_pattern
hash_pattern= re.compile(r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})\b')

#search_hashes
found_hashes= hash_pattern.findall(text)
print("\n   [+] Files Hashes found:{len(found_hashes)}")
for hash in found_hashes:
    print(f"   -> {hash}")

print("\n ======================================================================================================")
