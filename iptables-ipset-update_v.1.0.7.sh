#!/bin/bash
#
#.*Copyright (c) 2018, Fatih Celik
#.*All rights reserved.
#.*
#.*Redistribution and use in source and binary forms, with or without
#.*modification, are permitted provided that the following conditions are met:
#.*1. Redistributions of source code must retain the above copyright
#.*   notice, this list of conditions and the following disclaimer.
#.*2. Redistributions in binary form must reproduce the above copyright
#.*   notice, this list of conditions and the following disclaimer in the
#.*   documentation and/or other materials provided with the distribution.
#.*3. All advertising materials mentioning features or use of this software
#.*   must display the following acknowledgement:
#.*   This product includes software developed by the <organization>.
#.*4. Neither the name of the <organization> nor the
#.*   names of its contributors may be used to endorse or promote products
#.*   derived from this software without specific prior written permission.
#.*
#.*THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ''AS IS'' AND ANY
#.*EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#.*WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#.*DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
#.*DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#.*(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#.*LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#.*ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#.*(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#.*SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
####
# This script provides valid black list entries for iptables/ipset
# Make sure there are a tool chain which full of usable tools
# f.celik (Bntpro 2018) v 0.1:7 

for tool in "wget" "curl" "tr" "head" "perl" "egrep" "grep" "wc" "date" "cut" "logger"
do
        if [ ! -x "/usr/bin/${tool}" ] && [ ! -x "/bin/${tool}" ]; then
                echo "There is no $tool, so you shall not pass"
                exit 10;
        fi
done

if [ $# -ne 1 ]; then

regCond="^Name:\ .*"
ipSetListName=$( ipset list | egrep -A 1 "Name:" | grep -B 1 "list:set" | head -n 1 )
     if [[ ! $ipSetListName =~ $regCond ]]; then

	echo "Sorry, there must be at least one ipset configured as list:set type "
	echo "Or, you can pass existing ipset name as an argument while invoking this script"
   	echo ""
   	echo "Usage: iptables-ipset-update.sh <ipsetname>" 
   	exit 13
     fi

     ipSetListName=${ipSetListName#Name: }

else 
	par="$1"
  	res=$( ipset list | egrep -cE " ${par}$" )
  	if [ $res -eq 1 ]; then

    		ipSetListName="$par"

  	else 

    		echo "$par is not exist or not an ipset"
   		exit 16

	fi
fi

_date=$( date +%F-%H.%M.%S )
tmpdir=$( head -c 120 /dev/urandom | tr -cd "0-9A-Za-z" | head -c 24 )
mkdir "/tmp/${tmpdir}"
if [ $? -ne 0 ]; then 

	echo "Looks like you do not have permission to write under /tmp"
  	exip 11
fi

tmpDir="/tmp/${tmpdir}"
links[0]=https://www.binarydefense.com/banlist.txt
links[1]=https://rules.emergingthreats.net/blockrules/compromised-ips.txt
links[2]=https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
links[3]=https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset
links[4]=https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset
links[5]=https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
links[6]=https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/normshield_high_bruteforce.ipset
links[7]=https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/normshield_all_bruteforce.ipset
links[8]=https://iplists.firehol.org/files/normshield_all_attack.ipset

fetchLists(){
        for url in ${!links[@]}
        do
                fileName=$( echo ${links[$url]} | awk -F "/" ' NF>0 { print $NF }')
                /usr/bin/wget -t 1 --waitretry=30 -c "${links[$url]}" -O "${tmpDir}/${fileName}"
                if [ $? -ne 0 ]; then
                        /usr/bin/curl --retry 1 --retry-delay 30 "${links[$url]}" -O "${tmpDir}/${fileName}"
                fi
        done
        perl -lne 'print if ! /^\s*(#.*)?$/' ${tmpDir}/*.txt ${tmpDir}/*.netset ${tmpDir}/*.ipset | sort -uV > "${tmpDir}/pf-badhost.txt"
}

splitIntoCategories(){
	local count subnet
        echo "splitting into subnet categories..."
	egrep -v "/" ${tmpDir}/pf-badhost.txt > ${tmpDir}/ipset-badhosts
	egrep "/" ${tmpDir}/pf-badhost.txt | cut -d "/" -f 2 | sort -n | uniq -c \
	| while read -r count subnet 
   	do

		if [ $subnet -gt 8 ]; then

    			egrep "\/${subnet}$" "${tmpDir}/pf-badhost.txt" > "${tmpDir}/ipset-subnet-${subnet}"
			echo "subnet $subnet file created " 
			echo "The $count number of networks will be blocked in /${subnet}"

   		fi
	done
}

loadIPSets(){

	local res
	echo "generating ip sets.... "
	ipset create "${_date}-badhosts" hash:ip hashsize 16384 maxelem $( wc -l "${tmpDir}/ipset-badhosts" \
	| cut -d " " -f 1 ) > /dev/null 2>&1
	res=$?
 	if [ $res -ne 0 ] && [ $res -ne 1 ]; then

	    echo "ipset-${_date}-badhosts could not create"
	    exit 15

	fi

	while read -r line
	do

		ipset -! add "${_date}-badhosts" $line

	done < "${tmpDir}/ipset-badhosts"

	echo "... the next one"
 	maximum=$( wc -l ${tmpDir}/ipset-subnet-* | grep total | cut -d " " -f 2 )
   	ipset create "${_date}-subnets" hash:net family inet maxelem $maximum > /dev/null 2>&1 
  	res=$?
	if [ $res -ne 0 ] && [ $res -ne 1 ]; then
		echo "Ooops, I could not create ipset for subnets"
		exit 12
	fi

	while read -r line
	do

	    ipset -! add "${_date}-subnets" $line

   	done < <(cat ${tmpDir}/ipset-subnet* ) 

	echo "swapping old ipsets with newest ..."
	read -a listOfSets <<< $( ipset list "$ipSetListName" | grep -A 100 "Members:" | grep -v "Members:" )
	if [ ${#listOfSets[@]} -eq 0 ]; then

		echo "No old ip sets found" 
		ipset add $ipSetListName "${_date}-badhosts"
  		ipset add $ipSetListName "${_date}-subnets" 
  		logger -p local0.info "All Ip sets are updated, check log files for related dropped connection attempts"

	else

		for setName in ${!listOfSets[@]}
 		do

 			ipset del $ipSetListName ${listOfSets[$setName]}
			ipset destroy ${listOfSets[$setName]}

	 	done

	ipset add $ipSetListName "${_date}-badhosts"
  	ipset add $ipSetListName "${_date}-subnets"
	logger -p local0.info "All Ip sets are updated, check log files for related dropped connection attempts"
 
 	fi
}

fetchLists
splitIntoCategories
loadIPSets

# Cleaning out
 /bin/rm -rf "/tmp/${tmpdir}"
