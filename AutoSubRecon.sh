#!/bin/bash
set -e

echo "recon-2 [domain] [-l or -o for wordlist] "

if [ $# -lt 2 ];then
        echo "recon-2 [domain] [resolvers] [-l or -o for wordlist] "
        exit 1
fi

if [ ! -e wordlists ];then
        mkdir wordlists
fi

# Getting First word list

wget https://raw.githubusercontent.com/AlephNullSK/dnsgen/master/dnsgen/words.txt -O wordlists/dnsgen.txt
wget https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt -O wordlists/altdns.txt
domain_name=$1
resolvers="path/to/resolvers.txt"
altdns_words=wordlists/altdns.txt 
dnsgen_words=wordlists/dnsgen.txt

if [ ! -e wordlists/crunch.txt ];then
        crunch 1 4 qwertyuiopasdfghjklzxcvbnm1234 -o wordlists/crunch.txt
else
        echo "Skipping Create Crunch List"
fi

crunch_words=wordlists/crunch.txt
cat ${altdns_words} ${dnsgen_words} | sort | uniq >> wordlists/little_words.txt
little_words="wordlists/little_words.txt"
cat ${altdns_words} ${dnsgen_words} ${crunch_words} | sort | uniq >> wordlists/big_words.txt
big_words="wordlists/big_words.txt"

if [ "$2" == "-l" ];then
        word_list=$little_words
elif [ "$2" == "-b" ];then
        word_list=$big_words
else
        echo "word list can be -l or -b"
        exit 1

fi



#file 'nonemptyfile' exists and has a size of more than 0 bytes. -s


if [ ! -s "first-scan/subfinder.txt" ]; then
        mkdir -p first-scan
        sublister_path='python3 /home/soroush/domain-finders/passive/Sublist3r/sublist3r.py'
        $sublister_path -v -d $domain_name -o first-scan/sublister.txt
        subfinder -d $domain_name -v -all -o first-scan/subfinder.txt
        cat first-scan/sublister.txt first-scan/subfinder.txt| sort | uniq >> first-scan/merged-uniq-${domain_name}.txt
else
        echo "skiping First-scan with subfinder"

fi



#DNS BruteForce
if [ ! -s "bf-scan/shuffle-${domain_name}.txt" ];then
        mkdir -p bf-scan
        echo "Starting DNS bruteForce"
        echo "1) $word_list"
        echo "2) $domain_name"
        shuffledns -d $domain_name -w ${word_list} -r /home/soroush/resolvers.txt -sw -mode bruteforce -o bf-scan/shuffle-${domain_name}.txt
        # Merge Dns BruteForce & First scan Result >> static-dns-subdomains
        cat first-scan/merged-uniq-${domain_name}.txt bf-scan/shuffle-${domain_name}.txt | sort | uniq >> static-dns-${domain_name}.txt

else 
        echo "skiping DNS BrutForce"
fi 






#Dynamic BruteForce
if [ ! -s dynamic-${domain_name}/dnsgenout.txt ];then
        mkdir dynamic-${domain_name}
        cat static-dns-${domain_name}.txt | dnsgen -w $word_list - >> dynamic-${domain_name}/dnsgenout.txt
        altdns -i static-dns-${domain_name}.txt -w ${word_list} -o dynamic-${domain_name}/altdns.txt

        # Merge Dynamic List
        cat dynamic-${domain_name}/dnsgenout.txt dynamic-${domain_name}/altdns.txt | sort | uniq >> dynamic-${domain_name}/merged-dynamic-${domain_name}.txt

else
        echo "skiping Dynamic Bruth Force"

fi

# Merge Dynamic & Static Word List for Resolving...

static_final_words="static-dns-${domain_name}.txt"
dynamic_final_words="dynamic-${domain_name}/merged-dynamic-${domain_name}.txt"
mkdir -p final_result


# Find Valid Domains 
shuffledns -d ${domain_name} -list $dynamic_final_words -r ${resolvers} -mode resolve -o final_result/valid_dns_url.txt
cat $static_final_words >> final_result/valid_dns_url.txt

# Httpx test for discovering http 
httpx -l final_result/valid_dns_url.txt -sc -cl -title -o final_result/http_tested.txt
