#!/bin/bash
# Sphinx is a reconnaissance tool for external network tools.
# Author: Andreas Georgiou

# TO-DO List
# Add --install function
# Add --credits function
# Add --version function
# Validate --targets.txt file
# Sort .csv ips

echo "                    | \$\$       /\$\$                                        /\$\$        /\$\$\$\$\$\$ ";
echo "                    | \$\$      |__/                                      /\$\$\$\$       /\$\$\$_  \$\$";
echo "  /\$\$\$\$\$\$\$  /\$\$\$\$\$\$ | \$\$\$\$\$\$\$  /\$\$ /\$\$\$\$\$\$\$  /\$\$   /\$\$       /\$\$    /\$\$|_  \$\$      | \$\$\$\$\ \$\$";
echo " /\$\$_____/ /\$\$__  \$\$| \$\$__  \$\$| \$\$| \$\$__  \$\$|  \$\$ /\$\$/      |  \$\$  /\$\$/  | \$\$      | \$\$ \$\$ \$\$";
echo "|  \$\$\$\$\$\$ | \$\$  \ \$\$| \$\$  \ \$\$| \$\$| \$\$  \ \$\$ \  \$\$\$\$/        \  \$\$/\$\$/   | \$\$      | \$\$\ \$\$\$\$";
echo " \____  \$\$| \$\$  | \$\$| \$\$  | \$\$| \$\$| \$\$  | \$\$  >\$\$  \$\$         \  \$\$\$/    | \$\$      | \$\$ \ \$\$\$";
echo " /\$\$\$\$\$\$\$/| \$\$\$\$\$\$\$/| \$\$  | \$\$| \$\$| \$\$  | \$\$ /\$\$/\  \$\$         \  \$/    /\$\$\$\$\$\$ /\$\$|  \$\$\$\$\$\$/";
echo "|_______/ | \$\$____/ |__/  |__/|__/|__/  |__/|__/  \__/          \_/    |______/|__/ \______/ ";
echo "          | \$\$                                                                               ";
echo "          | \$\$                                                                               ";
echo "          |__/             The two most powerful warriors are Patience and Time.               ";
echo -e "\n"
echo -e "  Sphinx v0.9"
echo -e "  Author: Superhedgy"
echo -e "--------------------------------------------------------------------------------------------\n\n"

# check_ips Function - Validates, Expands CIDR ranges and Sorts IPs addresses
function check_ips
{
  regex='([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
  for x in $(cat $attacksurface);
  do
    if [[ $x =~ ^$regex\.$regex\.$regex\.$regex$ ]]; then
      echo $x >> sphinx_temp
    elif [[ $x =~ ^$regex\.$regex\.$regex\.$regex/[0-32] ]]; then
      nmap -sL -n $x | awk '{print $5}' | grep "[0-9].*" >> sphinx_temp
    elif [[ $x =~ ^$regex\.$regex\.$regex\.$regex/[0-32] ]]; then
      nmap -sL -n $x | awk '{print $5}' | grep "[0-9].*" >> sphinx_temp
    else
      echo -e "Error: '$x' is not a valid IP address.\n"
      exit 1
    fi
  done

  sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 sphinx_temp > validated_targets.txt

  rm -f sphinx_temp
}

# Trap Exit INT
trap "exit" INT

# Checks sudo privillege
if [ "$(whoami)" != 'root' ]; then
  echo -e " You run $sphinx as non-root user.\n"
  echo -e " Please run sphinx with sudo privilleges.\n"
  exit 1;
fi


if [ $# -ne 3 ]; && check_ips() then
  echo -e " Wrong Syntax !\n"
  echo -e " Usage: sudo ./$sphinx <targets.txt> -o <out.csv>\n"
  exit 1
fi

# Checks whether Target file exists
if [ ! -f $1 ]; then
    echo -e " $3 file not found!\n"
    exit 1
# Check output file exists
elif [ -f $3 ]; then
    echo -e " $3 already exists\n"
    exit 1
else
    echo '"IP Address","Port/Protocol","Domains","Operating System","OS Version","Notes"' >> $3
fi

declare -i counter
declare -i online
declare -i apps

online=0 #Counts online hosts
counter=0 #Counts the loops
apps=0 #Counts discovered web applications
OS="Unknown" #Defaut OS value
shodan_key=$(source shodan.key) #Shodan API Key
path=$(date +"%m-%d-%Y_%H_%M_%S") #Temporary file Path value

mkdir $path

for ip in $(cat $1);
do

  echo -e "\n[*] Fingerprinting Host $ip"
  # Host Timeout 15 minutes - Maximum Probe Retries 2 - T3 Normal
  sudo nmap -sSU -A --top-ports 200 --host-timeout 25 $ip > $path/$ip.nmap
  counter=$counter+1

  if grep -q -i "tcp.*open" $path/$ip.nmap > /dev/null 2>&1; then
    ports=$(grep -i "tcp.*open" $path/$ip.nmap | cut -d " " -f 1 | xargs | sed 's/ /, /g')
    online=$online+1

    #List Applications
    if echo $ports | grep -q -i "443/tcp" ; then
      echo https://$ip/ >> $path/apps.txt
      ctime=$(TZ=":US/Central" date -v +5M +'%d/%m/%Y %r') # Adds 5 minutes on US/Central timezone
      echo "https://$ip/"," sphinx_App","","","1.00","","NetPenScan","$ctime","","","150","True","True","False","True" >> scan_apps.csv
      let "apps+=1"
    fi

    if echo $ports | grep -q -i "80/tcp" ; then
      echo http://$ip/ >> $path/apps.txt
      echo "http://$ip/"," sphinx_App","","","1.00","","NetPenScan","7/11/2017 5:52:13 AM","","","150","True","True","False","True" >> scan_apps.csv
      let "apps+=1"
    fi

    if echo $ports | grep -q -i "8080/tcp" ; then
      echo http://$ip:8080/  >> $path/apps.txt
      echo "http://$ip:8080/"," sphinx_App","","","1.00","","NetPenScan","7/11/2017 5:52:13 AM","","","150","True","True","False","True" >> scan_apps.csv
      #echo '"'http://$ip:8080/'","'$ports'","'$domains'","'$OS'","'$OS_Version'","'$notes'"' > apps.txt
      let "apps+=1"
    fi

  else
    echo "[-] $ip : No open ports were detected"
    continue
  fi

  domains=""
  if grep -q -i "os details:" $path/$ip.nmap; then
    OS=$(grep -i "os details:" $path/$ip.nmap | sed 's/\;//g' | cut -d " " -f3)
    OS_Version=$(cat $path/$ip.nmap | grep -i "os details:" | cut -d " " -f4 )
  elif grep -q "Running (JUST GUESSING)" $path/$ip.nmap; then
    OS=$(grep "Running (JUST GUESSING)" $path/$ip.nmap | cut -d ":" -f2 | cut -d "," -f1 | cut -d "(" -f1)
#OS_Version=$(cat $ip.nmap | grep -i "JUST GUESSING" | cut -d " " -f4 )
  elif grep -q "OS:" $path/$ip.nmap; then
      OS=$(cat $path/$ip.nmap | grep "OS:" |  sed 's/\;//g' |cut -d " " -f4)
  elif grep -i -q "os guesses:" $path/$ip.nmap; then
      OS=$(cat $path/$ip.nmap | grep -i "os guesses:" | cut -d ":" -f2 | cut -d "(" -f1 )
  fi

  if echo $OS | grep -i -q "windows" ; then
      OS="Microsoft Windows Server"
  elif echo $OS | grep -i -q "linux" ; then
      OS="Linux"
  fi

  notes=$(cat $path/$ip.nmap | grep -i "Service Info:" | cut -c15- | sed 's/(//g;s/)//g;s/\;//g')

  echo -e "[+] $ip : $ports - $OS, $OS_Version"

  echo '"'$ip'","'$ports'","'$domains'","'$OS'","'$OS_Version'","'$notes'"' >> $3

  # This Line is Only for Debugging
  #rm $ip.nmap # Add before final release

  # Reverse DNS Service
  url="https://api.shodan.io/dns/reverse?ips=$ip&key=$shodan_key"

  tmp=$(curl -vs -o /dev/null ''$url'' 2>&1 | cut -d ":" -f2)

  if echo $tmp | grep -i -q "null" ; then
    domains=$(echo $tmp | rev |cut -c 2- | rev)
    echo -e "[+] Reverse DNS: $domains"
  else
    echo -e "[-] Reverse DNS: -"
  fi

done

reset

if [ -f $path/apps.txt ]; then
  echo -e "--------------------------------------------------------------------------------------------"
  echo -e " Discovered Web Applications"
  echo -e "--------------------------------------------------------------------------------------------"
  cat $path/apps.txt
  echo -e "\n"
fi

echo -e ""
echo -e "--------------------------------------------------------------------------------------------"

echo -e "\n  Reconnaissance Phase Completed ! \n"
say -r 200 "Reconaisance Phase Completed"

echo -e "  Scanned $counter hosts in total.\n"
say -r 200 "Scanned $counter hosts in total."

echo -e "  $online hosts were active.\n"
say -r 200 "$online hosts were active."

echo -e "  $apps web applications discovered.\n"
say -r 200 "$apps web applications discovered."

echo -e "\n--------------------------------------------------------------------------------------------"
