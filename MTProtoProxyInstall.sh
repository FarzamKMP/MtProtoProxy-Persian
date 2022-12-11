#!/bin/bash
regex='^[0-9]+$'
function RemoveMultiLineUser() {
	local SECRET_T
	SECRET_T=$(python3 -c 'import config;print(getattr(config, "USERS",""))')
	SECRET_T=$(echo "$SECRET_T" | tr "'" '"')
	python3 -c "import re;f = open('config.py', 'r');s = f.read();p = re.compile('USERS\\s*=\\s*\\{.*?\\}', re.DOTALL);nonBracketedString = p.sub('', s);f = open('config.py', 'w');f.write(nonBracketedString)"
	echo "" >>config.py
	echo "USERS = $SECRET_T" >>config.py
}
function GetRandomPort() {
	if ! [ "$INSTALLED_LSOF" == true ]; then
		echo "dar hale nasbe package lsof, lotfan sabur bashid"
		apt-get -y install lsof >/dev/null
		local RETURN_CODE
		RETURN_CODE=$?
		if [ $RETURN_CODE -ne 0 ]; then
			echo "$(tput setaf 3)Warning!$(tput sgr 0) lsof ba movafaghiat nasb NASHOD. Port entekhab shode be soorate random por ast, lotfan port digari ra entekhab konid!"
		else
			INSTALLED_LSOF=true
		fi
	fi
	PORT=$((RANDOM % 16383 + 49152))
	if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null; then
		GetRandomPort
	fi
}
function ListUsersAndSelect() {
	clear
	SECRET=$(python3 -c 'import config;print(getattr(config, "USERS",""))')
	SECRET_COUNT=$(python3 -c 'import config;print(len(getattr(config, "USERS","")))')
	if [ "$SECRET_COUNT" == "0" ]; then
		echo "$(tput setaf 1)Error:$(tput sgr 0) Shoma Secret Nadarid!"
		exit 4
	fi
	RemoveMultiLineUser #Regenerate USERS only in one line
	SECRET=$(echo "$SECRET" | tr "'" '"')
	echo "$SECRET" >tempSecrets.json
	SECRET_ARY=()
	mapfile -t SECRET_ARY < <(jq -r 'keys[]' tempSecrets.json)
	echo "List karbarane server shoma :"
	COUNTER=1
	NUMBER_OF_SECRETS=${#SECRET_ARY[@]}
	for i in "${SECRET_ARY[@]}"; do
		echo "	$COUNTER) $i"
		COUNTER=$((COUNTER + 1))
	done
	read -r -p "lotfan ba estefade az index karbari ra entekhab konid:" USER_TO_LIMIT
	if ! [[ $USER_TO_LIMIT =~ $regex ]]; then
		echo "$(tput setaf 1)Error:$(tput sgr 0) Vorudi shomareh ye dorosti nist"
		exit 1
	fi
	if [ "$USER_TO_LIMIT" -lt 1 ] || [ "$USER_TO_LIMIT" -gt "$NUMBER_OF_SECRETS" ]; then
		echo "$(tput setaf 1)Error:$(tput sgr 0) Shomareh dar dastres nist!"
		exit 1
	fi
	USER_TO_LIMIT=$((USER_TO_LIMIT - 1))
	KEY=${SECRET_ARY[$USER_TO_LIMIT]}
}
function GenerateConnectionLimiterConfig() {
	LIMITER_CONFIG=""
	LIMITER_FILE=""
	for user in "${!limits[@]}"; do
		LIMITER_CONFIG+='"'
		LIMITER_CONFIG+=$user
		LIMITER_CONFIG+='": '
		LIMITER_CONFIG+=${limits[$user]}
		LIMITER_CONFIG+=" , "
		LIMITER_FILE+="$user;${limits[$user]}\n"
	done
	if ! [[ ${#limits[@]} == 0 ]]; then
		LIMITER_CONFIG=${LIMITER_CONFIG::${#LIMITER_CONFIG}-2}
	fi
}
function RestartService() {
	pid=$(systemctl show --property MainPID mtprotoproxy)
	arrPID=(${pid//=/ })
	pid=${arrPID[1]}
	kill -USR2 "$pid"
}
function PrintErrorJson() {
	echo "{\"ok\":false,\"msg\":\"$1\"}"
	exit 1
}
function PrintOkJson() {
	echo "{\"ok\":true,\"msg\":\"$1\"}"
}
function GetSecretFromUsername() {
	rm -f tempSecrets.json
	KEY="$1"
	SECRET=$(python3 -c 'import config;print(getattr(config, "USERS",""))')
	SECRET_COUNT=$(python3 -c 'import config;print(len(getattr(config, "USERS","")))')
	if [ "$SECRET_COUNT" == "0" ]; then
		PrintErrorJson "You have no secrets"
	fi
	RemoveMultiLineUser #Regenerate USERS only in one line
	SECRET=$(echo "$SECRET" | tr "'" '"')
	echo "$SECRET" >>tempSecrets.json
	SECRET=$(jq -r --arg k "$KEY" '.[$k]' tempSecrets.json)
	if [ "$SECRET" == "null" ]; then
		PrintErrorJson "This secret does not exist."
	fi
}
#User must run the script as root
if [[ $EUID -ne 0 ]]; then
	echo "Lotfan in script ra be halate karbare arshad, Root vared konid!"
	exit 1
fi
distro=$(awk -F= '/^NAME/{print $2}' /etc/os-release)
clear
#Check if user already installed Proxy
if [ -d "/opt/mtprotoproxy" ]; then
	SCRIPT_LOCATION=$(realpath "$0")
	cd /opt/mtprotoproxy/ || exit 2
	if [ "$#" -ge 1 ]; then
		OPTION=$1
		if [ "$OPTION" == "list" ]; then
			if [ "$#" == 1 ]; then #list all of the secret and usernames
				SECRET=$(python3 -c 'import config;print(getattr(config, "USERS",""))')
				SECRET_COUNT=$(python3 -c 'import config;print(len(getattr(config, "USERS","")))')
				if [ "$SECRET_COUNT" == "0" ]; then
					PrintErrorJson "Shoma Secret Nadarid"
				fi
				SECRET=$(echo "$SECRET" | tr "'" '"')
				echo "{\"ok\":true,\"msg\":$SECRET}"
			else #Send the secret of the user
				GetSecretFromUsername "$2"
				PrintOkJson "$SECRET"
			fi
		fi
	else
		echo "Shoma dar hale hazer mtprotoproxy ra nasb kardid. che kari mikhahid anjam dahid?"
		echo "  1 ) Didane tamame etesalat"
		echo "  2 ) berooz resani narmafzare proxy"
		echo "  3 ) taghire TAG tablighat"
		echo "  4 ) ezafe kardane Secret"
		echo "  5 ) hazf Secret"
		echo "  6 ) taghire mahdoodiate etesal be server"
		echo "  7 ) taghire tarikh enghezaye karbar"
		echo "  8 ) Sahmieh ye karbar ra taghir dahid"
		echo "  9 ) Skhate ghavanin firewall"
		echo "  10) HAZFE PROXY"
		echo "  11) Darbare ma"
		echo "  * ) khoruj"
		read -r -p "lotfan adad ra vared konid: " OPTION
	fi
	case $OPTION in
	#View connection links
	1)
		clear
		echo "$(tput setaf 3)Dar hale gereftane IP adress.$(tput sgr 0)"
		PUBLIC_IP="$(curl https://api.ipify.org -sS)"
		CURL_EXIT_STATUS=$?
		if [ $CURL_EXIT_STATUS -ne 0 ]; then
			PUBLIC_IP="YOUR_IP"
		fi
		PORT=$(python3 -c 'import config;print(getattr(config, "PORT",-1))')
		SECRET=$(python3 -c 'import config;print(getattr(config, "USERS",""))')
		SECRET_COUNT=$(python3 -c 'import config;print(len(getattr(config, "USERS","")))')
		TLS_DOMAIN=$(python3 -c 'import config;print(getattr(config, "TLS_DOMAIN", "www.google.com"))')
		if [ "$SECRET_COUNT" == "0" ]; then
			echo "$(tput setaf 1)Error:$(tput sgr 0) Shoma Secret nadarid nemishe chizi neshun dad"
			exit 4
		fi
		RemoveMultiLineUser #Regenerate USERS only in one line
		SECRET=$(echo "$SECRET" | tr "'" '"')
		echo "$SECRET" >tempSecrets.json
		SECRET_ARY=()
		mapfile -t SECRET_ARY < <(jq -r 'keys[]' tempSecrets.json)
		#Print
		for user in "${SECRET_ARY[@]}"; do
			SECRET=$(jq --arg u "$user" -r '.[$u]' tempSecrets.json)
			s=$(python3 -c "print(\"ee\" + \"$SECRET\" + \"$TLS_DOMAIN\".encode().hex())")
			echo "$user: tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=$s"
			echo
		done
		sed -i '/^$/d' config.py #Remove empty lines
		rm -f tempSecrets.json
		;;
	#Update
	2)
		read -r -p "agar shoma sahmieh gozashtid pas az estefade ghat mishan, edame bedim ?(y/n) " OPTION
		OPTION="$(echo $OPTION | tr '[A-Z]' '[a-z]')"
		if [[ "$OPTION" == "y" ]]; then
			systemctl stop mtprotoproxy
			mv /opt/mtprotoproxy/config.py /tmp/config.py
			git pull
			mv /tmp/config.py /opt/mtprotoproxy/config.py
			#Update cryptography and uvloop
			pip3.8 install --upgrade cryptography uvloop
			systemctl start mtprotoproxy
			echo "Proxy berooz shod"
		fi
		;;
	#Change AD_TAG
	3)
		TAG=$(python3 -c 'import config;print(getattr(config, "AD_TAG",""))')
		OldEmptyTag=false
		if [ -z "$TAG" ]; then
			OldEmptyTag=true
			echo "benazar tage tablighati shoma khali ast, tag ra az https://t.me/mtproxybot daryaft konid va inja vared konid:"
		else
			echo "Tage alane shoma $TAG ast. baraye hazf kardan enter ra click konid. dar gheyre in soorat TAG jadid ra vared konid:"
		fi
		read -r TAG
		if [ -n "$TAG" ] && [ "$OldEmptyTag" = true ]; then
			#This adds the AD_TAG to end of file
			echo "" >>config.py #Adds a new line
			TAGTEMP="AD_TAG = "
			TAGTEMP+='"'
			TAGTEMP+="$TAG"
			TAGTEMP+='"'
			echo "$TAGTEMP" >>config.py
		elif [ -n "$TAG" ] && [ "$OldEmptyTag" = false ]; then
			# This replaces the AD_TAG
			TAGTEMP='"'
			TAGTEMP+="$TAG"
			TAGTEMP+='"'
			sed -i "s/^AD_TAG =.*/AD_TAG = $TAGTEMP/" config.py
		elif [ -z "$TAG" ] && [ "$OldEmptyTag" = false ]; then
			# This part removes the last AD_TAG
			sed -i '/^AD_TAG/ d' config.py
		fi
		sed -i '/^$/d' config.py #Remove empty lines
		RestartService
		echo "Done"
		;;
	#New secret
	4)
		#API Usage: bash MTProtoProxyInstall.sh 4 <USERNAME> <SECRET> -> Do not define secret to generate a random secret
		SECRETS=$(python3 -c 'import config;print(getattr(config, "USERS","{}"))')
		SECRET_COUNT=$(python3 -c 'import config;print(len(getattr(config, "USERS","")))')
		SECRETS=$(echo "$SECRETS" | tr "'" '"')
		SECRETS="${SECRETS::-1}" #Remove last char "}" here
		if [ "$#" -ge 2 ]; then #Get username
			NEW_USR="$2"
			if [ "$#" -ge 3 ]; then #This means secret should not be created randomly
				SECRET="$3"
				#Validate secret
				SECRET="$(echo $SECRET | tr '[A-Z]' '[a-z]')"
				if ! [[ $SECRET =~ ^[0-9a-f]{32}$ ]]; then
					PrintErrorJson "Secret motabar nist. bayad hexadecimal bashad va shamele 32 horuf."
				fi
			else #Create a random secret
				SECRET="$(hexdump -vn "16" -e ' /1 "%02x"' /dev/urandom)"
			fi
		else #User mode
			echo "$(tput setaf 3)Warning!$(tput sgr 0) az alamat haye khas manande: \" , ' , $ ya... estefade nakonid baraye username."
			read -r -p "Lotfan username ra vared konid:" -e -i "NewUser" NEW_USR
			echo "Shoma mikhahid Secret ra dasti vared konid ya baraye shoma automatic besazim?"
			echo "   1) Vared kardan secret dasti"
			echo "   2) sakhte Secret automatic"
			read -r -p "Lotfan yeki ra entekhab konid [1-2]: " -e -i 2 OPTION
			case $OPTION in
			1)
				echo "vared konid ye secret 32 horufi ke shamele 0-9 va a-f bashad: "
				read -r SECRET
				#Validate secret
				SECRET="$(echo $SECRET | tr '[A-Z]' '[a-z]')"
				if ! [[ $SECRET =~ ^[0-9a-f]{32}$ ]]; then
					echo "$(tput setaf 1)Error:$(tput sgr 0) vared konin Secret hexadecimal ra ke shamele 32 harf bashad"
					exit 1
				fi
				;;
			2)
				SECRET="$(hexdump -vn "16" -e ' /1 "%02x"' /dev/urandom)"
				echo "OK, yeki sakhtam: $SECRET"
				;;
			*)
				echo "$(tput setaf 1)Invalid option$(tput sgr 0)"
				exit 1
				;;
			esac
		fi
		RemoveMultiLineUser #Regenerate USERS only in one line
		if [ "$SECRET_COUNT" -ne 0 ]; then
			SECRETS+=','
		fi
		SECRETS+='"'
		SECRETS+="$NEW_USR"
		SECRETS+='": "'
		SECRETS+="$SECRET"
		SECRETS+='"}'
		sed -i '/^USERS\s*=.*/ d' config.py #Remove USERS
		echo "" >>config.py
		echo "USERS = $SECRETS" >>config.py
		sed -i '/^$/d' config.py #Remove empty lines
		RestartService
		PUBLIC_IP="$(curl https://api.ipify.org -sS)"
		CURL_EXIT_STATUS=$?
		if [ $CURL_EXIT_STATUS -ne 0 ]; then
			PUBLIC_IP="YOUR_IP"
		fi
		PORT=$(python3 -c 'import config;print(getattr(config, "PORT",-1))')
		TLS_DOMAIN=$(python3 -c 'import config;print(getattr(config, "TLS_DOMAIN", "www.google.com"))')
		s=$(python3 -c "print(\"ee\" + \"$SECRET\" + \"$TLS_DOMAIN\".encode().hex())")
		if [ "$#" -ge 2 ]; then
			echo "{\"ok\":true,\"msg\":{\"link\":\"tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=$s\",\"secret\":\"$SECRET\"}}"
		else
			echo
			echo "You can now connect to your server with this secret with this link:"
			echo "tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=$s"
		fi
		;;
	#Revoke secret
	5)
		#API usage: bash MTProtoProxyInstall.sh 5 <USERNAME>
		if [ "$#" -ge 2 ]; then #Get username
			GetSecretFromUsername "$2" #However the SECRET variable is not used; This is just used to verify that the user exist
		else
			ListUsersAndSelect
		fi
		#remove expiry date and connection limits
		bash "$SCRIPT_LOCATION" 6 "$KEY" 0 &>/dev/null
		bash "$SCRIPT_LOCATION" 7 "$KEY" &>/dev/null
		#remove the secret
		SECRET=$(jq -c --arg u "$KEY" 'del(.[$u])' tempSecrets.json)
		sed -i '/^USERS\s*=.*/ d' config.py #Remove USERS
		echo "" >>config.py
		echo "USERS = $SECRET" >>config.py
		sed -i '/^$/d' config.py #Remove empty lines
		RestartService
		rm -f tempSecrets.json
		if [ "$#" -ge 2 ]; then
			PrintOkJson ""
		else
			echo "Done"
		fi
		;;
	#Connection limits
	6)
		#API Usage: bash MTProtoProxyInstall.sh 6 <USERNAME> <LIMIT> -> Pass zero for unlimited
		if [ "$#" -ge 3 ]; then
			GetSecretFromUsername "$2"
		else
			ListUsersAndSelect
		fi
		declare -A limits
		while IFS= read -r line; do
			if [ "$line" != "" ]; then
				arrIN=(${line//;/ })
				limits+=(["${arrIN[0]}"]="${arrIN[1]}")
			fi
		done <"limits_bash.txt"
		if [ "$#" -ge 3 ]; then
			MAX_USER=$3
			if ! [[ $MAX_USER =~ $regex ]]; then
				PrintErrorJson "The limit is not a valid number."
			fi
		else
			if [ ${limits[$KEY]+abc} ]; then
				MAX_USER=$((limits[$KEY] / 8))
				echo "Current limit is $MAX_USER concurrent users. (${limits[$KEY]} connections)"
			else
				echo "In karbar hich mahdoodiati nadarad"
			fi
			read -r -p "lotfan hade aksare karbarani ke mikhan be in karbar vasl shavand ra vared konid; baraye bi nahayat 0 ra vared konid: " MAX_USER
			if ! [[ $MAX_USER =~ $regex ]]; then
				echo "$(tput setaf 1)Error:$(tput sgr 0) vorudi adade motabari nist"
				exit 1
			fi
		fi
		MAX_USER=$((MAX_USER * 8))
		if [ "$MAX_USER" = "0" ]; then
			unset limits["$KEY"]
		else
			limits[$KEY]=$MAX_USER
		fi
		GenerateConnectionLimiterConfig
		echo -e "$LIMITER_FILE" >"limits_bash.txt"
		sed -i '/^USER_MAX_TCP_CONNS\s*=.*/ d' config.py #Remove settings
		echo "" >>config.py
		echo "USER_MAX_TCP_CONNS = { $LIMITER_CONFIG }" >>config.py
		sed -i '/^$/d' config.py #Remove empty lines
		RestartService
		if [ "$#" -ge 3 ]; then
			PrintOkJson ""
		else
			echo "Anjam Shod"
		fi
		;;
	#Expiry date
	7)
		#API Usage: bash MTProtoProxyInstall.sh 7 <USERNAME> <DATE> -> Pass nothing as <DATE> to remove; Date format is dd/mm/yyyy
		if [ "$#" -ge 2 ]; then
			GetSecretFromUsername "$2"
			DATE="$3"
		else
			ListUsersAndSelect
			read -r -p "tarikhe engheza ra be in halat vared konin rooz/mah/sal(MESAL 11/09/2019). baraye hazf hichi vared nakonid: " DATE
		fi
		if [[ $DATE == "" ]]; then
			j=$(jq -c --arg k "$KEY" 'del(.[$k])' limits_date.json)
		else
			if ! [[ $DATE =~ ^[0-9]{2}/[0-9]{2}/[0-9]{4}$ ]]; then 
				if [ "$#" -ge 2 ]; then
					PrintErrorJson "Formate tarikh motabar nist"
				else
					echo "Format motabar nist (DD/MM/YYYY)"
					exit 1
				fi
			fi
			j=$(jq -c --arg k "$KEY" --arg v "$DATE" '.[$k] = $v' limits_date.json)
		fi
		echo -e "$j" >limits_date.json
		#Save it to the config.py
		sed -i '/^USER_EXPIRATIONS\s*=.*/ d' config.py #Remove settings
		echo "" >>config.py
		echo "USER_EXPIRATIONS = $j" >>config.py
		sed -i '/^$/d' config.py #Remove empty lines
		RestartService
		if [ "$#" -ge 2 ]; then
			PrintOkJson ""
		else
			echo "Done"
		fi
		;;
	#Quota limit stuff
	8)
		#API Usage: bash MTProtoProxyInstall.sh 8 <USERNAME> <LIMIT> -> Pass nothing as <LIMIT> to remove; The number is in bytes
		if [ "$#" -ge 2 ]; then
			GetSecretFromUsername "$2"
			LIMIT="$3"
		else
			ListUsersAndSelect
			read -r -p "mahdoodiate karbaran ra be soorate byte vared konid. shoma mitavanid az pasvand haye kb, mb, gb estefade konid. baraye hazf hichi vared nakonid: " LIMIT
		fi
		if [[ $LIMIT == "" ]]; then
			j=$(jq -c --arg k "$KEY" 'del(.[$k])' limits_quota.json)
		else
			LIMIT="$(echo $LIMIT | tr '[A-Z]' '[a-z]')"
			MULTIPLIER=1
			case "$LIMIT" in
			*kb)
				MULTIPLIER=1024
				LIMIT=${LIMIT::-2}
				;;
			*mb)
				MULTIPLIER=$((1024*1024))
				LIMIT=${LIMIT::-2}
				;;
			*gb)
				MULTIPLIER=$((1024*1024*1024))
				LIMIT=${LIMIT::-2}
				;;
			esac
			if ! [[ $LIMIT =~ $regex ]]; then
				if [ "$#" -ge 2 ]; then
					PrintErrorJson "Formate adad motabar nist"
				else
					echo "$(tput setaf 1)Error:$(tput sgr 0) vorudi adad motabar nist"
					exit 1
				fi
			fi
			LIMIT=$((MULTIPLIER*LIMIT))
			j=$(jq -c --arg k "$KEY" --argjson v "$LIMIT" '.[$k] = $v' limits_quota.json)
		fi
		echo -e "$j" >limits_quota.json
		#Save it to the config.py
		sed -i '/^USER_DATA_QUOTA\s*=.*/ d' config.py #Remove settings
		echo "" >>config.py
		echo "USER_DATA_QUOTA = $j" >>config.py
		sed -i '/^$/d' config.py #Remove empty lines
		RestartService
		if [ "$#" -ge 2 ]; then
			PrintOkJson ""
		else
			echo "Done"
		fi
		;;
	#Firewall rules
	9)
		PORT=$(python3 -c 'import config;print(getattr(config, "PORT",-1))')
		if [[ $distro =~ "Ubuntu" ]]; then
			echo "ufw allow $PORT/tcp"
		elif [[ $distro =~ "Debian" ]]; then
			echo "iptables -A INPUT -p tcp --dport $PORT --jump ACCEPT"
			echo "iptables-save > /etc/iptables/rules.v4"
		fi
		read -r -p "Do you want to apply these rules?[y/n] " -e -i "y" OPTION
		if [ "$OPTION" == "y" ] || [ "$OPTION" == "Y" ]; then
			if [[ $distro =~ "Ubuntu" ]]; then
				ufw allow "$PORT"/tcp
			elif [[ $distro =~ "Debian" ]]; then
				iptables -A INPUT -p tcp --dport "$PORT" --jump ACCEPT
				iptables-save >/etc/iptables/rules.v4
			fi
		fi
		;;
	#Uninstall proxy
	10)
		read -r -p "man bazi az package ha manande python ra negah midaram. aya mikhahid MTProto-Proxy ra hazf konid?(y/n) " OPTION
		OPTION="$(echo $OPTION | tr '[A-Z]' '[a-z]')"
		case $OPTION in
		"y")
			PORT=$(python3 -c 'import config;print(getattr(config, "PORT",-1))')
			systemctl stop mtprotoproxy
			systemctl disable mtprotoproxy
			rm -rf /opt/mtprotoproxy /etc/systemd/system/mtprotoproxy.service
			systemctl daemon-reload
			if [[ $distro =~ "Ubuntu" ]]; then
				ufw delete allow "$PORT"/tcp
			elif [[ $distro =~ "Debian" ]]; then
				iptables -D INPUT -p tcp --dport "$PORT" --jump ACCEPT
				iptables-save >/etc/iptables/rules.v4
			fi
			echo "Ok it's done."
			;;
		esac
		;;
	# About
	11)
		echo "MTProtoInstaller be zabane farsi sakhte shode tavasote Amirfarzam baraye hemayat az ma dar channel telegram DEVEFUN Join bedid."
		echo "manba dar https://github.com/MalmWareMan"
		echo "manba mostaghim, REPO https://github.com/MalmWareMan/MtProtoProxy-Persian"
		;;
	esac
	exit
fi
#Variables
SECRETS=""
SECRET=""
SECRET_END_ARY=()
USERNAME_END_ARY=()
TAG=""
COUNTER=1
echo "be nasbe automatic mtprotoproxy khosh amadid"
echo "sakhte shode tavasote MalWareMan"
echo "manba dar https://github.com/MalmWareMan"
echo "repo'e script dar github : https://github.com/MalmWareMan/MtProtoProxy-Persian"
echo "Hal kami etelaat az shoma daryaft mikonim"
echo ""
echo ""
read -r -p "yek port baraye goosh dadan entekhab konid (-1 baraye random sakhtan): " -e -i "443" PORT
if [[ $PORT -eq -1 ]]; then
	GetRandomPort
	echo "man porte $PORT ra baraye shoma entekhab kardam"
fi
#Lets check if the PORT is valid
if ! [[ $PORT =~ $regex ]]; then
	echo "$(tput setaf 1)Error:$(tput sgr 0) Vorudi adade motabari nist"
	exit 1
fi
if [ "$PORT" -gt 65535 ]; then
	echo "$(tput setaf 1)Error:$(tput sgr 0): adad bayad kamtar az 65536 bashad"
	exit 1
fi
#Now the username and secrets
declare -A limits
echo "$(tput setaf 3)Warning!$(tput sgr 0) az horufe khas manande: \" , ' , $ ya... dar username estefade nakonid"
while true; do
	echo "hal username ra be man bedahid, az username baraye sakhte secret estefade mishavad. "
	read -r -e -i "MTSecret$COUNTER" USERNAME
	echo "Secret ra dasti vared mikonid ya automatic sakhte shavad ?"
	echo "   1) sakhte secret dasti"
	echo "   2) sakhte secret automatic"
	read -r -p "lotfan yeki ra entekhab konid [1-2]: " -e -i 2 OPTION
	case $OPTION in
	1)
		echo "lotfan yek secret 32 horufe shamele 0-9 va a-f vared konid(hexadecimal): "
		read -r SECRET
		#Validate length
		SECRET="$(echo $SECRET | tr '[A-Z]' '[a-z]')"
		if ! [[ $SECRET =~ ^[0-9a-f]{32}$ ]]; then
			echo "$(tput setaf 1)Error:$(tput sgr 0) lotfan secret hexadecimal bashad va 32 horuf ra shamel bashad"
			exit 1
		fi
		;;
	2)
		SECRET="$(hexdump -vn "16" -e ' /1 "%02x"' /dev/urandom)"
		echo "OK I created one: $SECRET"
		;;
	*)
		echo "$(tput setaf 1)Invalid option$(tput sgr 0)"
		exit 1
		;;
	esac
	SECRET_END_ARY+=("$SECRET")
	USERNAME_END_ARY+=("$USERNAME")
	#Now add them to secrets
	SECRETTEMP='"'
	SECRETTEMP+="$USERNAME"
	SECRETTEMP+='":"'
	SECRETTEMP+="$SECRET"
	SECRETTEMP+='"'
	SECRETS+="$SECRETTEMP , "
	#Setup limiter
	read -r -p "aya mikhahid karbarane mahdoodi be in server vasl shavand ?(y/n) " -e -i "n" OPTION
	OPTION="$(echo $OPTION | tr '[A-Z]' '[a-z]')"
	case $OPTION in
	'y')
		read -r -p "chand karbar mikhahid be in secret vasl shavand? " OPTION
		if ! [[ $OPTION =~ $regex ]]; then
			echo "$(tput setaf 1)Error:$(tput sgr 0) vorudi adade motabar nist"
			exit 1
		fi
		#Multiply number of connections by 8. You can manualy change this. Read more: https://github.com/alexbers/mtprotoproxy/blob/master/mtprotoproxy.py#L202
		OPTION=$((OPTION * 8))
		limits+=(["$USERNAME"]="$OPTION")
		;;
	'n') ;;

	*)
		echo "$(tput setaf 1)Invalid option$(tput sgr 0)"
		exit 1
		;;
	esac
	read -r -p "mikhahid secret digari ezafe konid ?(y/n) " -e -i "n" OPTION
	OPTION="$(echo $OPTION | tr '[A-Z]' '[a-z]')"
	case $OPTION in
	'y') ;;

	'n')
		break
		;;
	*)
		echo "$(tput setaf 1)Invalid option$(tput sgr 0)"
		exit 1
		;;
	esac
	COUNTER=$((COUNTER + 1))
done
SECRETS=${SECRETS::${#SECRETS}-2}
if [ ${#limits[@]} -gt 0 ]; then
	GenerateConnectionLimiterConfig
fi
#Set secure mode
echo
echo "1) bedoone mahdoodiat"
echo '2) "dd" secrets va etesalate TLS'
echo "3) faghat etesalate TLS"
read -r -p "aya mikhahid etesalat ra mahdood konid? yeki ra entekhab konid: " -e -i "3" OPTION
case $OPTION in
'1') 
	SECURE_MODE="MODES = { \"classic\": True, \"secure\": True, \"tls\": True }"
	;;
'2')
	SECURE_MODE="MODES = { \"classic\": False, \"secure\": True, \"tls\": True }"
	;;
'3')
	SECURE_MODE="MODES = { \"classic\": False, \"secure\": False, \"tls\": True }"
	;;
*)
	echo "$(tput setaf 1)Invalid option$(tput sgr 0)"
	exit 1
	;;
esac
#Now setup the tag
read -r -p "aya mikhahid tag tablighati ezafe konid?(y/n) " -e -i "n" OPTION
if [[ "$OPTION" == "y" || "$OPTION" == "Y" ]]; then
	echo "$(tput setaf 1)Note:$(tput sgr 0) karbarane admin va ozv shodegan channel ra dar pin nemibinand"
	echo "dar telegram, be @MTProxybot beravid, ip va $PORT ra be onvane port dar robot vared konid. sepas be onvane secret, $SECRET ra vared konid."
	echo "robot be shoma matni ra be onvane tag midahad, dar inja vared konid:"
	read -r TAG
fi
#Change host mask
read -r -p "lotfan yek mizban ra entekhab konid: (TLS_DOMAIN): " -e -i "www.cloudflare.com" TLS_DOMAIN
#Now lets install
read -n 1 -s -r -p "baraye nasb ENTER ra click konid"
clear
if [[ $distro =~ "Ubuntu" ]]; then
	apt update
	apt-get -y install python3 python3-pip sed git curl jq ca-certificates
elif [[ $distro =~ "Debian" ]]; then
	apt-get update
	apt-get install -y jq ca-certificates iptables-persistent iptables git sed curl wget python3 python3-pip
	#Firewall
	iptables -A INPUT -p tcp --dport "$PORT" --jump ACCEPT
	iptables-save >/etc/iptables/rules.v4
else
	echo "system amele shoma poshtibani nemishavad!"
	exit 2
fi
timedatectl set-ntp on #Make the time accurate by enabling ntp
#This libs make proxy faster
pip3 install cryptography uvloop
if ! [ -d "/opt" ]; then
	mkdir /opt
fi
cd /opt || exit 2
git clone https://github.com/alexbers/mtprotoproxy.git
cd mtprotoproxy || exit 2
#Now edit the config file
chmod 0777 config.py
echo "PORT = $PORT
USERS = { $SECRETS }
USER_MAX_TCP_CONNS = { $LIMITER_CONFIG }
TLS_DOMAIN = \"$TLS_DOMAIN\"
" >config.py
if [ -n "$TAG" ]; then
	TAGTEMP="AD_TAG = "
	TAGTEMP+='"'
	TAGTEMP+="$TAG"
	TAGTEMP+='"'
	echo "$TAGTEMP" >>config.py
fi
echo "$SECURE_MODE" >> config.py
echo -e "$LIMITER_FILE" >> "limits_bash.txt"
echo "{}" >> "limits_date.json"
echo "{}" >> "limits_quota.json"
#Setup firewall
echo "tanzimate ghavanine firewall"
if [[ $distro =~ "Ubuntu" ]]; then
	if dpkg --get-selections | grep -q "^ufw[[:space:]]*install$" >/dev/null; then
		ufw allow "$PORT"/tcp
	else
		echo
		read -r -p 'benazar "UFW"(Firewall) nasb nist, aya mikhahid nasbesh konid?(y/n) ' -e -i "y" OPTION
		case $OPTION in
		"y" | "Y")
			apt-get install ufw
			ufw enable
			ufw allow ssh
			ufw allow "$PORT"/tcp
			;;
		esac
	fi
	#Use BBR on user will
	if ! [ "$(sysctl -n net.ipv4.tcp_congestion_control)" = "bbr" ]; then
		echo
		read -r -p "Aya mikhahid az BBR estefade konid? BBR be shoma komak mikonad proxy sari tar amal konad.(y/n) " -e -i "y" OPTION
		case $OPTION in
		"y" | "Y")
			echo 'net.core.default_qdisc=fq' | tee -a /etc/sysctl.conf
			echo 'net.ipv4.tcp_congestion_control=bbr' | tee -a /etc/sysctl.conf
			sysctl -p
			;;
		esac
	fi
fi
#Now lets create the service
cd /etc/systemd/system || exit 2
echo "[Unit]
Description = MTProto Proxy Service
After=network.target

[Service]
Type = simple
ExecStart = /usr/bin/python3 /opt/mtprotoproxy/mtprotoproxy.py
StartLimitBurst=0

[Install]
WantedBy = multi-user.target" >mtprotoproxy.service
systemctl daemon-reload
systemctl enable mtprotoproxy
systemctl start mtprotoproxy
tput setaf 3
printf "%$(tput cols)s" | tr ' ' '#'
tput sgr 0
echo "OK, tamoom shod man yek service sakhtam baraye khamush va roshan kardane proxy"
echo 'estefade konid az "systemctl start mtprotoproxy" ya "systemctl stop mtprotoproxy" baraye shoroo va khamush kardane proxy'
echo
echo "Az in link ha baraye vasl shodan be proxy estefade konid:"
PUBLIC_IP="$(curl https://api.ipify.org -sS)"
CURL_EXIT_STATUS=$?
[ $CURL_EXIT_STATUS -ne 0 ] && PUBLIC_IP="YOUR_IP"
COUNTER=0
for i in "${SECRET_END_ARY[@]}"; do
	s=$(python3 -c "print(\"ee\" + \"$SECRET\" + \"$TLS_DOMAIN\".encode().hex())")
	echo "${USERNAME_END_ARY[$COUNTER]}: tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=$s"
	COUNTER=$COUNTER+1
done
