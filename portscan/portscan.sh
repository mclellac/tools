#!/bin/bash -e
#############################################################################
#   PORT SCAN BY SICINTHEMIND
#     Can install to /usr/bin/ and it will run anywhere, saving the files
#     in the current working directory.
#     Alt: ln -s $(PWD)/portscan.sh /usr/bin/portscan.sh
#############################################################################
if [ -z $1 ]; then
    echo "fail... add an argument"
    echo " $0 <ip.add.re.ss> <hostname>(opt)"
    exit 1
fi
#############################################################################
#	SET VARIABLES TO BE USED THROUGHOUT THE SCRIPT
#############################################################################

ip=$1
#host=$2
udpscanports="21,22,25,42,53,67,68,88,123,110,111,137,138,139,161,162,194,389,1512,5901,5900,6900"
scriptopts="default"
tcpresults="$(pwd)"'/tcp_'"$ip".nmap
udpresults="$(pwd)"'/udp_'"$ip".nmap
defresults="$(pwd)"'/enum_'"$ip".nmap
vulresults="$(pwd)"'/vuln_'"$ip"

#############################################################################
#	TCP SCANNING
#############################################################################
echo "Scanning TCP Ports"
if [ -f $tcpresults ]; then
    if [[ $(find "$tcpresults" -mtime +1 -print) ]]; then
        nmap -T5 -Pn -p- -sT $ip -oN $tcpresults
    else
        echo "   -- Skipping"
    fi
else
    nmap -T5 -Pn -p- -sT $ip -oN $tcpresults
fi
opentcpports=$(grep open $tcpresults | grep -vE "^$|^#"  | cut -d '/' -f 1)
portcount=$(echo "$opentcpports" | grep -vE "^$|^#"  | wc -l)
tports=""
tportsc=0
if [ $portcount -gt 0 ]; then
    lines=0
    while read -r line; do
        lines=$(($lines + 1))
        if [ $lines -eq 1 ]; then
            tports="$line"
            tportsc=$(($tportsc + 1))
        else
            tports+=",$line"
            tportsc=$(($tportsc + 1))
        fi
    done <<< "$opentcpports"
fi
#############################################################################
#	UDP SCANNING
#############################################################################
echo "Scanning UDP Ports"
if [ -f $udpresults ]; then
    if [[ $(find "$udpresults" -mtime +1 -print) ]]; then
        echo "Nmap Options: --max-retries 2 -T3 -p $udpscanports -sU $ip -oN $udpresults"
        nmap --max-retries 2 -T3 -p $udpscanports -sU $ip -oN $udpresults
    else
        echo "   -- Skipping"
    fi
else
    nmap --max-retries 2 -T3 -p $udpscanports -sU $ip -oN $udpresults
fi

openudpports=$(grep open $udpresults | grep -v filtered | grep -vE "^$|^#" | cut -d '/' -f 1 )
portcount=$(grep open $udpresults | grep -v filtered | grep -vE "^$|^#" | wc -l)
uports=""
uportsc=0
if [ $portcount -gt 0 ]; then
    lines=0
    while read -r line; do
        lines=$(($lines + 1))
        if [ $lines -eq 1 ]; then
            uports="$line"
            uportsc=$(($uportc + 1))
        else
            uports+=",$line"
            uportsc=$(($uportc + 1))
        fi
    done <<< "$openudpports"
fi
if [ $uportsc -eq 0 ]; then 
    if [ $tportsc -eq 0 ]; then
         echo "Something might be wrong..."
         echo "No ports are open"'!'
         exit 1;
    else 
        allports="T:$tports"
    fi
else
    allports="U:$uports,T:$tports"
fi
#############################################################################
#	Version Scanning all ports
#############################################################################
echo "Identified ports: $allports"
echo "Executing Full Enumeration Scan"
if [ -f $defresults ]; then
    if [[ $(find "$defresults" -mtime +1 -print) ]]; then
		echo "Nmap Options: -T3 -Pn -p $allports -sV $ip -oN $defresults"
        nmap -T3 -Pn -p $allports -sV $ip -oN $defresults
    else
        echo "   -- Skipping"
    fi
else
    nmap -T3 -Pn -p $allports -sV $ip -oN $defresults
fi
allopenports=$(grep open $defresults)
# | cut -d '/' -f 1)
lines=0
httpset="false"
smtpset="false"
snmpset="false"
dnsset="false"
vncset="false"
msrpc="false"
tftpset="false"
ftpset="false"
mssqlset="false"
smbset="false"
nfsset="false"
mysqlset="false"
while read -r line; do
    lines=$(($lines + 1))
    indport=$(echo "$line" | cut -d '/' -f 1)
    if [[ $line == *"http"* ]] && [ $httpset == "false" ]; then
        scriptopts+=",http-vuln*"
        httpset="true"
    fi
    if [[ $line == *"smtp"* ]] && [ $smtpset == "false" ]; then
        scriptopts+=",smtp-vuln*"
	smtpset="true"
    fi
    if [[ $line == *"domain"* ]] && [ $dnsset == "false" ]; then
        scriptopts+=",dns-*"
        dnsset="true"
    fi
    if [[ $line == *"snmp"* ]] && [ $snmpset == "false" ]; then
        scriptopts+=",snmp-info"
        snmpset="true"
    fi
    if [[ $line == *"vnc"* ]] && [ $vncset == "false" ]; then
        scriptopts+=",realvnc-auth-bypass.nse,vnc-info.nse,vnc-title.nse"
	#scriptopts+=",realvnc-auth-bypass.nse,vnc-*"
        vncset="true"
    fi
    if [[ $line == *"msrpc"* ]] && [ $msrpc == "false" ]; then
        scriptopts+=",msrpc-enum.nse"
        msrpc="true"
    fi
    if [[ $line == *"tftp"* ]] && [ $tftpset == "false" ]; then
        scriptopts+=",tftp-enum.nse"
        tftpset="true"
    fi
    if [[ $line == *"ftp"* ]] && [ $ftpset == "false" ]; then
        scriptopts+=",ftp-anon.nse,ftp-bounce.nse,ftp-libopie.nse,ftp-proftpd-backdoor.nse,ftp-syst.nse,ftp-vsftpd-backdoor.nse,ftp-vuln-cve2010-4221.nse"
        ftpset="true"
    fi
    if [[ $line == *"ms-sql"* ]] && [ $mssqlset == "false" ]; then
        scriptopts+=",ms-sql-config.nse,ms-sql-config.nse,ms-sql-dac.nse,ms-sql-dump-hashes.nse,ms-sql-empty-password.nse,ms-sql-hasdbaccess.nse,ms-sql-info.nse,ms-sql-ntlm-info.nse"
        mssqlset="true"
    fi
    if [[ $line == *"microsoft-ds"* ]] || [[ $line == *"netbios-ssn"* ]] && [ $smbset == "false" ]; then
        scriptopts+=",smb-enum-shares.nse,smb-vuln-*,smb-enum-users.nse,smb-system-info.nse,smb-double-pulsar-backdoor.nse,smb2-vuln-uptime.nse,smb2-time.nse,smb-os-discovery.nse,smb-server-stats.nse,smb2-security-mode.nse"
        smbset="true"
    fi
    if [[ $line == *"mysql"* ]] && [ $mysqlset == "false" ]; then
        scriptopts+=",mysql-audit.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse"
        mysqlset="true"	
    fi
    case $indport in
        2049)
            if [ $nfsset == "false" ]; then
                scriptopts+=",nfs-*"
                nfsset="true"
            fi

            ;;
        *)
            ;;
    esac
done <<< "$allopenports"
echo "Performing aggressive vulnerability scan"
if [ -f $vulresults ]; then
    if [[ $(find "$vulresults" -mtime +1 -print) ]]; then
	echo "Nmap Options: -T3 -Pn -p $allports -sV --script=$scriptopts $ip -oN $vulresults"
        nmap -vv -T3 -O -Pn -p $allports -sV --script=$scriptopts $ip -oA $vulresults 
    else
        echo " -- Skipping rescan"
    fi
else
    echo "Nmap Options: -T3 -Pn -p $allports -sV --script=$scriptopts $ip -oN $vulresults"
    nmap -T3 -Pn -O -p $allports -sV --script=$scriptopts $ip -oA $vulresults
fi
clear
cat $vulresults.nmap
