# AutoSubRecon

usage:
  recon-2 [domain] [resolvers] [-l or -o for wordlist] 

  This script automates subdomain enumeration by combining passive scanning with dynamic and brute force techniques. It integrates various wordlists for DNS brute force, utilizes tools like subfinder, shuffledns, and dnsgen to discover subdomains, and validates them through resolvers. Additionally, httpx is used to test the discovered domains for HTTP services, making the process more comprehensive.
  ![External Recon](https://github.com/user-attachments/assets/57d67452-e304-439d-88c3-306246ce7318)
