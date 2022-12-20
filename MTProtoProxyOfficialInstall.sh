#!/bin/bash
function GetRandomPort() {
	if ! [ "$INSTALLED_LSOF" == true ]; then
		echo "Dar hale nasbe package lsof, lotfan sabur bashid"
		if [[ $distro =~ "CentOS" ]]; then
			yum -y -q install lsof
		elif [[ $distro =~ "Ubuntu" ]] || [[ $distro =~ "Debian" ]]; then
			apt-get -y install lsof >/dev/null
		fi
		local RETURN_CODE
		RETURN_CODE=$?
		if [ $RETURN_CODE -ne 0 ]; then
			echo "$(tput setaf 3)Warning!$(tput sgr 0) package lsof be dorosti nasb nashod, shayad port dar hale estefade ast."
		else
			INSTALLED_LSOF=true
		fi
	fi
	PORT=$((RANDOM % 16383 + 49152))
	if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null; then
		GetRandomPort
	fi
}
function GenerateService() {
	local ARGS_STR
	ARGS_STR="-u nobody -H $PORT"
	for i in "${SECRET_ARY[@]}"; do # Add secrets
		ARGS_STR+=" -S $i"
	done
	if [ -n "$TAG" ]; then
		ARGS_STR+=" -P $TAG "
	fi
	if [ -n "$TLS_DOMAIN" ]; then
		ARGS_STR+=" -D $TLS_DOMAIN "
	fi
	if [ "$HAVE_NAT" == "y" ]; then
		ARGS_STR+=" --nat-info $PRIVATE_IP:$PUBLIC_IP "
	fi
	NEW_CORE=$((CPU_CORES - 1))
	ARGS_STR+=" -M $NEW_CORE $CUSTOM_ARGS --aes-pwd proxy-secret proxy-multi.conf"
	SERVICE_STR="[Unit]
Description=MTProxy
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/MTProxy/objs/bin
ExecStart=/opt/MTProxy/objs/bin/mtproto-proxy $ARGS_STR
Restart=on-failure
StartLimitBurst=0

[Install]
WantedBy=multi-user.target"
}
#User must run the script as root
if [[ "$EUID" -ne 0 ]]; then
	echo "Please run this script as root"
	exit 1
fi
regex='^[0-9]+$'
distro=$(awk -F= '/^NAME/{print $2}' /etc/os-release)
clear
if [ -d "/opt/MTProxy" ]; then
	echo "shoma dar hale hazer servis MTProxy ra nasb kardid, che kari az dastam barmiad?"
	echo "  1 ) neshan dadane link etesalat"
	echo "  2 ) taghire TAG"
	echo "  3 ) Ezafe kardane secret"
	echo "  4 ) Hazfe secret"
	echo "  5 ) taghire tedade karkonan"
	echo "  6 ) Taghire tanzimate NAT"
	echo "  7 ) Taghire shakhsi sazi estedlal ha"
	echo "  8 ) sakhte ghavanine FireWall"
	echo "  9 ) hazfe MTProxy"
	echo "  10) darbare ma"
	echo "  *) khoruj"
	read -r -p "lotfan yek adad ra vared konid: " OPTION
	source /opt/MTProxy/objs/bin/mtconfig.conf #Load Configs
	case $OPTION in
	#Show connections
	1)
		clear
		echo "$(tput setaf 3)Dar hale daryafte IP address shoma.$(tput sgr 0)"
		PUBLIC_IP="$(curl https://api.ipify.org -sS)"
		CURL_EXIT_STATUS=$?
		if [ $CURL_EXIT_STATUS -ne 0 ]; then
			PUBLIC_IP="YOUR_IP"
		fi
		HEX_DOMAIN=$(printf "%s" "$TLS_DOMAIN" | xxd -pu)
		HEX_DOMAIN="$(echo $HEX_DOMAIN | tr '[A-Z]' '[a-z]')"
		for i in "${SECRET_ARY[@]}"; do
			if [ -z "$TLS_DOMAIN" ]; then
				echo "tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=dd$i"
			else
				echo "tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=ee$i$HEX_DOMAIN"
			fi
		done
		;;
	#Change TAG
	2)
		if [ -z "$TAG" ]; then
			echo "benazar TAG tablighati shoma khali ast, shoma mitavanid in TAG ra az https://t.me/mtproxybot daryaft va dar inja vared konid:"
		else
			echo "Tage dar hale estefade: $TAG Ast. Agar mikhahid an ra pak konid enter ra click konid. dar gheyre in soorat tage jadid ra vared konid:"
		fi
		read -r TAG
		cd /etc/systemd/system || exit 2
		systemctl stop MTProxy
		GenerateService
		echo "$SERVICE_STR" >MTProxy.service
		systemctl daemon-reload
		systemctl start MTProxy
		cd /opt/MTProxy/objs/bin/ || exit 2
		sed -i "s/^TAG=.*/TAG=\"$TAG\"/" mtconfig.conf
		echo "Done"
		;;
	#Add secret
	3)
		if [ "${#SECRET_ARY[@]}" -ge 16 ]; then
			echo "$(tput setaf 1)Error$(tput sgr 0) Shoma nemitavanid bish az 16 secret dashte bashid"
			exit 1
		fi
		echo "shoma mayelid secret ra dasti besazid ya automatic?"
		echo "   1) Sakhte Secret dasti"
		echo "   2) sakhte secret automatic"
		read -r -p "lotfan yeki ra entekhab konid [1-2]: " -e -i 2 OPTION
		case $OPTION in
		1)
			echo "yek matne 32 harfi ke shamele 0-9 va a-f ast ra vared konid (hexadecimal): "
			read -r SECRET
			#Validate length
			SECRET="$(echo $SECRET | tr '[A-Z]' '[a-z]')"
			if ! [[ $SECRET =~ ^[0-9a-f]{32}$ ]]; then
				echo "$(tput setaf 1)Error:$(tput sgr 0) secret bayad be soorate hexadecimal bashad va 32 harf dashte bashad"
				exit 1
			fi
			;;
		2)
			SECRET="$(hexdump -vn "16" -e ' /1 "%02x"' /dev/urandom)"
			echo "OK, man yeki sakhtam $SECRET"
			;;
		*)
			echo "$(tput setaf 1)Invalid option$(tput sgr 0)"
			exit 1
			;;
		esac
		SECRET_ARY+=("$SECRET")
		#Add secret to config
		cd /etc/systemd/system || exit 2
		systemctl stop MTProxy
		GenerateService
		echo "$SERVICE_STR" >MTProxy.service
		systemctl daemon-reload
		systemctl start MTProxy
		cd /opt/MTProxy/objs/bin/ || exit 2
		SECRET_ARY_STR=${SECRET_ARY[*]}
		sed -i "s/^SECRET_ARY=.*/SECRET_ARY=($SECRET_ARY_STR)/" mtconfig.conf
		echo "Done"
		PUBLIC_IP="$(curl https://api.ipify.org -sS)"
		CURL_EXIT_STATUS=$?
		if [ $CURL_EXIT_STATUS -ne 0 ]; then
			PUBLIC_IP="YOUR_IP"
		fi
		echo
		echo "Shoma mitavanid be server ba linke zir motasel shavid :"
		echo "tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=dd$SECRET"
		;;
	#Revoke Secret
	4)
		NUMBER_OF_SECRETS=${#SECRET_ARY[@]}
		if [ "$NUMBER_OF_SECRETS" -le 1 ]; then
			echo "Akharin secret ra nemishe hazf kard"
			exit 1
		fi
		echo "secret ra baraye hazf entekhab konid:"
		COUNTER=1
		for i in "${SECRET_ARY[@]}"; do
			echo "  $COUNTER) $i"
			COUNTER=$((COUNTER + 1))
		done
		read -r -p "Karbari ra ba estefade az index entekhab karde baraye hazf: " USER_TO_REVOKE
		if ! [[ $USER_TO_REVOKE =~ $regex ]]; then
			echo "$(tput setaf 1)Error:$(tput sgr 0) The input is not a valid number"
			exit 1
		fi
		if [ "$USER_TO_REVOKE" -lt 1 ] || [ "$USER_TO_REVOKE" -gt "$NUMBER_OF_SECRETS" ]; then
			echo "$(tput setaf 1)Error:$(tput sgr 0) Invalid number"
			exit 1
		fi
		USER_TO_REVOKE1=$((USER_TO_REVOKE - 1))
		SECRET_ARY=("${SECRET_ARY[@]:0:$USER_TO_REVOKE1}" "${SECRET_ARY[@]:$USER_TO_REVOKE}")
		cd /etc/systemd/system || exit 2
		systemctl stop MTProxy
		GenerateService
		echo "$SERVICE_STR" >MTProxy.service
		systemctl daemon-reload
		systemctl start MTProxy
		cd /opt/MTProxy/objs/bin/ || exit 2 || exit 2
		SECRET_ARY_STR=${SECRET_ARY[*]}
		sed -i "s/^SECRET_ARY=.*/SECRET_ARY=($SECRET_ARY_STR)/" mtconfig.conf
		echo "Done"
		;;	
	#Change CPU workers
	5)
		CPU_CORES=$(nproc --all)
		echo "man fahmidam ke server shoma daraye $CPU_CORES hasteh ast. Agar shoma bekhayd man mitoonam proxy ra rooye hasteh haye shoma config konam. in amal baes mishavad ke proxy dar $CPU_CORES karkonad. baraye barkhi dalayel proxy ha mamoolan dar 16 hasteh az kar mioftan pas adadi ra az 1-16 vared konid:"
		read -r -p "shoma chand hasteh ye kargar baraye proxy mikhahid: " -e -i "$CPU_CORES" CPU_CORES
		if ! [[ $CPU_CORES =~ $regex ]]; then #Check if input is number
			echo "$(tput setaf 1)Error:$(tput sgr 0) vorudi adade motabari nist"
			exit 1
		fi
		if [ "$CPU_CORES" -lt 1 ]; then #Check range of workers
			echo "$(tput setaf 1)Error:$(tput sgr 0) adadi bish az 1 vared konid."
			exit 1
		fi
		if [ "$CPU_CORES" -gt 16 ]; then
			echo "(tput setaf 3)Warning:$(tput sgr 0) maghadiri bish az 16 baese borooz moshkelati dar ayandeh mishavad, in risk be paye khodetun ast."
		fi
		#Save
		cd /etc/systemd/system || exit 2
		systemctl stop MTProxy
		GenerateService
		echo "$SERVICE_STR" >MTProxy.service
		systemctl daemon-reload
		systemctl start MTProxy
		cd /opt/MTProxy/objs/bin/ || exit 2
		sed -i "s/^CPU_CORES=.*/CPU_CORES=$CPU_CORES/" mtconfig.conf
		echo "Anjam shod"
		;;
	#Change NAT types
	6)
		#Try to autodetect private ip: https://github.com/angristan/openvpn-install/blob/master/openvpn-install.sh#L230
		IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
		HAVE_NAT="n"
		if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
			HAVE_NAT="y"
		fi
		read -r -p "Aya server shoma poshte NAT ast? (shoma ehtemalan be in niaz darid agar az AWS estefade mikonid)(y/n) " -e -i "$HAVE_NAT" HAVE_NAT
		if [[ "$HAVE_NAT" == "y" || "$HAVE_NAT" == "Y" ]]; then
			PUBLIC_IP="$(curl https://api.ipify.org -sS)"
			read -r -p "lotfan ip omumi khod ra vared konid: " -e -i "$PUBLIC_IP" PUBLIC_IP
			if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
				echo "man fahmidam ke $IP ip shakhsi shoma ast. lotfan an ra taeed konid."
			else
				IP=""
			fi
			read -r -p "lotfan IP shakhsi ra vared konid: " -e -i "$IP" PRIVATE_IP
		fi
		cd /opt/MTProxy/objs/bin/ || exit 2
		sed -i "s/^HAVE_NAT=.*/HAVE_NAT=\"$HAVE_NAT\"/" mtconfig.conf
		sed -i "s/^PUBLIC_IP=.*/PUBLIC_IP=\"$PUBLIC_IP\"/" mtconfig.conf
		sed -i "s/^PRIVATE_IP=.*/PRIVATE_IP=\"$PRIVATE_IP\"/" mtconfig.conf
		echo "Done"
		;;
	#Change other args
	7)
		echo "agar mikhahid az estedlale khasi baraye run kardane mtproxy estefade konid vared konid; gheyre in soorat tanha enter ra click kinid:"
		read -r -e -i "$CUSTOM_ARGS" CUSTOM_ARGS
		#Save
		cd /etc/systemd/system || exit 2
		systemctl stop MTProxy
		GenerateService
		echo "$SERVICE_STR" >MTProxy.service
		systemctl daemon-reload
		systemctl start MTProxy
		cd /opt/MTProxy/objs/bin/ || exit 2
		sed -i "s/^CUSTOM_ARGS=.*/CUSTOM_ARGS=\"$CUSTOM_ARGS\"/" mtconfig.conf
		echo "Anjam shod"
		;;
	#Firewall rules
	8)
		if [[ $distro =~ "CentOS" ]]; then
			echo "firewall-cmd --zone=public --add-port=$PORT/tcp"
			echo "firewall-cmd --runtime-to-permanent"
		elif [[ $distro =~ "Ubuntu" ]]; then
			echo "ufw allow $PORT/tcp"
		elif [[ $distro =~ "Debian" ]]; then
			echo "iptables -A INPUT -p tcp --dport $PORT --jump ACCEPT"
			echo "iptables-save > /etc/iptables/rules.v4"
		fi
		read -r -p "aya in ghavanin ra ghabul mikonid?[y/n] " -e -i "y" OPTION
		if [ "$OPTION" == "y" ] || [ "$OPTION" == "Y" ]; then
			if [[ $distro =~ "CentOS" ]]; then
				firewall-cmd --zone=public --add-port="$PORT"/tcp
				firewall-cmd --runtime-to-permanent
			elif [[ $distro =~ "Ubuntu" ]]; then
				ufw allow "$PORT"/tcp
			elif [[ $distro =~ "Debian" ]]; then
				iptables -A INPUT -p tcp --dport "$PORT" --jump ACCEPT
				iptables-save >/etc/iptables/rules.v4
			fi
		fi
		;;
	#Uninstall proxy
	9)
		read -r -p "man bazi az package ha ra manande \"Development Tools\" negah midaram. aya mikhahid mtproxy ra hazf konid?(y/n) " OPTION
		case $OPTION in
		"y" | "Y")
			cd /opt/MTProxy || exit 2
			systemctl stop MTProxy
			systemctl disable MTProxy
			if [[ $distro =~ "CentOS" ]]; then
				firewall-cmd --remove-port="$PORT"/tcp
				firewall-cmd --runtime-to-permanent
			elif [[ $distro =~ "Ubuntu" ]]; then
				ufw delete allow "$PORT"/tcp
			elif [[ $distro =~ "Debian" ]]; then
				iptables -D INPUT -p tcp --dport "$PORT" --jump ACCEPT
				iptables-save >/etc/iptables/rules.v4
			fi
			rm -rf /opt/MTProxy /etc/systemd/system/MTProxy.service
			systemctl daemon-reload
			sed -i '\|cd /opt/MTProxy/objs/bin && bash updater.sh|d' /etc/crontab
			if [[ $distro =~ "CentOS" ]]; then
				systemctl restart crond
			elif [[ $distro =~ "Ubuntu" ]] || [[ $distro =~ "Debian" ]]; then
				systemctl restart cron
			fi
			echo "OK, anjam shod"
			;;
		esac
		;;
	# About
	11)
		echo "MTProtoInstaller farsi va update shode tavasote AmirFarzam "
		echo "manba dar https://github.com/TelegramMessenger/MTProxy"
		echo "Github repo, script: https://github.com/MalmWareMan/MtProtoProxy-Persian"
		;;
	esac
	exit
fi
SECRET_ARY=()
if [ "$#" -ge 2 ]; then
	AUTO=true
	# Parse arguments like: https://stackoverflow.com/4213397
	while [[ "$#" -gt 0 ]]; do
		case $1 in
			-s|--secret) SECRET_ARY+=("$2"); shift ;;
		 	-p|--port) PORT=$2; shift ;;
			-t|--tag) TAG=$2; shift ;;
			--workers) CPU_CORES=$2; shift ;;
			--disable-updater) ENABLE_UPDATER="n" ;;
			--tls) TLS_DOMAIN="$2"; shift ;;
			--custom-args) CUSTOM_ARGS="$2"; shift;;
			--no-nat) HAVE_NAT="n" ;;
			--no-bbr) ENABLE_BBR="n" ;;
		esac
		shift
	done
	#Check secret
	if [[ ${#SECRET_ARY[@]} -eq 0 ]];then
		echo "$(tput setaf 1)Error:$(tput sgr 0) lotfan hade aghal yek secret ra vared konid:"
		exit 1
	fi
	for i in "${SECRET_ARY[@]}"; do
		if ! [[ $i =~ ^[0-9a-f]{32}$ ]]; then
			echo "$(tput setaf 1)Error:$(tput sgr 0) horufe hexadecimal ra vared konid va secret bayad 32 harf bashad. Error baraye secret $i"
			exit 1
		fi
	done
	#Check port
	if [ -z ${PORT+x} ]; then #Check random port
		GetRandomPort
		echo "man $PORT ra be onvane porte shoma entekhab kardam."
	fi
	if ! [[ $PORT =~ $regex ]]; then #Check if the port is valid
		echo "$(tput setaf 1)Error:$(tput sgr 0) Vorudi adade motabar nist"
		exit 1
	fi
	if [ "$PORT" -gt 65535 ]; then
		echo "$(tput setaf 1)Error:$(tput sgr 0): adad bayad kamtar az 65536 bashad"
		exit 1
	fi
	#Check NAT
	if [[ "$HAVE_NAT" != "n" ]]; then
		PRIVATE_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
		PUBLIC_IP="$(curl https://api.ipify.org -sS)"
		HAVE_NAT="n"
		if echo "$PRIVATE_IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
			HAVE_NAT="y"
		fi
	fi
	#Check other stuff
	if [ -z ${CPU_CORES+x} ]; then CPU_CORES=$(nproc --all); fi
	if [ -z ${ENABLE_UPDATER+x} ]; then ENABLE_UPDATER="y"; fi
	if [ -z ${TLS_DOMAIN+x} ]; then TLS_DOMAIN="www.cloudflare.com"; fi
	if [ -z ${ENABLE_BBR+x} ]; then ENABLE_UPDATER="y"; fi
else
	#Variables
	SECRET=""
	TAG=""
	echo "be MTPROTO-Proxy ba nasbe auto khosh amadid!"
	echo "Sakhte shode tavasote AmirFarzam"
	echo "man MTProxy rasmi ra baraye shoma nasb khaham kard"
	echo "Source at https://github.com/TelegramMessenger/MTProxy"
	echo "Github repo of script: https://github.com/MalmWareMan/MtProtoProxy-Persian"
	echo "hal man barkhi etelaat az shoma daryaft mikonam"
	echo ""
	echo ""
	#Proxy Port
	read -r -p "porti ra entekhab konid ke proxy be an goosh dahad (-1 sakhte random): " -e -i "443" PORT
	if [[ $PORT -eq -1 ]]; then #Check random port
		GetRandomPort
		echo "man $PORT ra be onvane port entekhab kardam."
	fi
	if ! [[ $PORT =~ $regex ]]; then #Check if the port is valid
		echo "$(tput setaf 1)Error:$(tput sgr 0) adade vorudi motabar nist"
		exit 1
	fi
	if [ "$PORT" -gt 65535 ]; then
		echo "$(tput setaf 1)Error:$(tput sgr 0): adad bayad kamtar az 65536 bashad"
		exit 1
	fi
	while true; do
		echo "mikhahid secret dasti ya automatic sakhte shavad?"
		echo "   1) Sakhte secret dasti"
		echo "   2) Sakhte secret random"
		read -r -p "lotfan yeki ra entekhab konid [1-2]: " -e -i 2 OPTION
		case $OPTION in
		1)
			echo "Enter a 32 character string filled by 0-9 and a-f(hexadecimal): "
			read -r SECRET
			#Validate length
			SECRET="$(echo $SECRET | tr '[A-Z]' '[a-z]')"
			if ! [[ $SECRET =~ ^[0-9a-f]{32}$ ]]; then
				echo "$(tput setaf 1)Error:$(tput sgr 0) horufe hexadecimal ra vared konid ke 32 harf dashte bashad"
				exit 1
			fi
			;;
		2)
			SECRET="$(hexdump -vn "16" -e ' /1 "%02x"' /dev/urandom)"
			echo "OK, man yeki sakhtam: $SECRET"
			;;
		*)
			echo "$(tput setaf 1)Invalid option$(tput sgr 0)"
			exit 1
			;;
		esac
		SECRET_ARY+=("$SECRET")
		read -r -p "aya mikhahid secret digari ezafe konid?(y/n) " -e -i "n" OPTION
		case $OPTION in
		'y' | "Y")
			if [ "${#SECRET_ARY[@]}" -ge 16 ]; then
				echo "$(tput setaf 1)Error$(tput sgr 0) nemitavanid bish az 16 secret dashte bashid"
				break
			fi
			;;

		'n' | "N")
			break
			;;
		*)
			echo "$(tput setaf 1)Invalid option$(tput sgr 0)"
			exit 1
			;;
		esac
	done
	#Now setup the tag
	read -r -p "aya mikhahid yek TAG tablighati ezafe konid?(y/n) " -e -i "n" OPTION
	if [[ "$OPTION" == "y" || "$OPTION" == "Y" ]]; then
		echo "$(tput setaf 1)Note:$(tput sgr 0) admin ha va karbarane join shode channel ra pin nemibinand."
		echo "dar telegram, dar @MTProxybot IP server ra vared konid va $PORT ra be onvane port. va secret ra vared konid=> $SECRET"
		echo "Bot be shoma yek string midahad ke inja vared konid:"
		read -r TAG
	fi
	#Get CPU Cores
	CPU_CORES=$(nproc --all)
	echo "man fahmidam server shoma daraye $CPU_CORES hasteh ast. agr mikhahid mitavanam proxy ra dar tamame hasteh ye shoma faal konam. In baes mishavad az $CPU_CORES hasteh kar bekeshim. baraye barkhi dalayel proxy adr hasteh haye balaye 16 ta kar nemikonad. lotfan adadi beyne 1 ta 16 entekhab konid:"
	read -r -p "Chand hasteh shoroo be faaliat konad ? " -e -i "$CPU_CORES" CPU_CORES
	if ! [[ $CPU_CORES =~ $regex ]]; then #Check if input is number
		echo "$(tput setaf 1)Error:$(tput sgr 0) Vorudi adade motabari nist"
		exit 1
	fi
	if [ "$CPU_CORES" -lt 1 ]; then #Check range of workers
		echo "$(tput setaf 1)Error:$(tput sgr 0) Adadi vorudi bish az 1 bashad."
		exit 1
	fi
	if [ "$CPU_CORES" -gt 16 ]; then
		echo "$(tput setaf 3)Warning:$(tput sgr 0) vorudi bish az 16 momken ast daraye moshkel dashte bashad pas be ohdeh ye khodetun ast riske an."
	fi
	#Secret and config updater
	read -r -p "Aya mikhahid berooz resani khodkar ra faal konid? Man \"proxy-secret\" va \"proxy-multi.conf\" ra har shab berooz resani mikonam. Pishnahad mishavad faal konid.[y/n] " -e -i "y" ENABLE_UPDATER
	#Change host mask
	read -r -p "yek mizban entekhab konid ke DPI rooye an hasas nabashad (TLS_DOMAIN). khali bogzarid ta FAKE_TLS gheyre faal shavad. faal sazi in gozine automatid secret DD ra gheyre faal mikonad " -e -i "www.cloudflare.com" TLS_DOMAIN
	#Use nat status for proxies behind NAT
	#Try to autodetect private ip: https://github.com/angristan/openvpn-install/blob/master/openvpn-install.sh#L230
	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	HAVE_NAT="n"
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		HAVE_NAT="y"
	fi
	read -r -p "aya server shoma poshte nat ast ? (shoma ehtemalan be an niaz darid agar az AWS estefade mikonid)(y/n) " -e -i "$HAVE_NAT" HAVE_NAT
	if [[ "$HAVE_NAT" == "y" || "$HAVE_NAT" == "Y" ]]; then
		PUBLIC_IP="$(curl https://api.ipify.org -sS)"
		read -r -p "lotfan IP omumi ra vared konid: " -e -i "$PUBLIC_IP" PUBLIC_IP
		if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
			echo "man fahmidam $IP ,Ip shakhsi shomast. lotfan taeed konid."
		else
			IP=""
		fi
		read -r -p "Lotfan ip shakhsi ra vared konid " -e -i "$IP" PRIVATE_IP
	fi
	#Other arguments
	echo "agar mikhahid estedlale shakhsi varede proxy konid inja vared konid; dar gheyre in soorat enter ra click konid."
	read -r CUSTOM_ARGS
	#Install
	read -n 1 -s -r -p "baraye nasb enter ra click konid..."
	clear
fi
#Now install packages
if [[ $distro =~ "CentOS" ]]; then
	yum -y install epel-release
	yum -y install openssl-devel zlib-devel curl ca-certificates sed cronie vim-common
	yum -y groupinstall "Development Tools"
elif [[ $distro =~ "Ubuntu" ]] || [[ $distro =~ "Debian" ]]; then
	apt-get update
	apt-get -y install git curl build-essential libssl-dev zlib1g-dev sed cron ca-certificates vim-common
fi
timedatectl set-ntp on #Make the time accurate by enabling ntp
#Clone and build
cd /opt || exit 2
git clone -b gcc10 https://github.com/krepver/MTProxy.git
cd MTProxy || exit 2
make            #Build the proxy
BUILD_STATUS=$? #Check if build was successful
if [ $BUILD_STATUS -ne 0 ]; then
	echo "$(tput setaf 1)Error:$(tput sgr 0) sakhtar na movafagh $BUILD_STATUS"
	echo "dar hale pak kardane file haye project..."
	rm -rf /opt/MTProxy
	echo "Anjam Shod !"
	exit 3
fi
cd objs/bin || exit 2
curl -s https://core.telegram.org/getProxySecret -o proxy-secret
STATUS_SECRET=$?
if [ $STATUS_SECRET -ne 0 ]; then
	echo "$(tput setaf 1)Error:$(tput sgr 0) Nemitavanim download konim proxy-secret az telegram"
fi
curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf
STATUS_SECRET=$?
if [ $STATUS_SECRET -ne 0 ]; then
	echo "$(tput setaf 1)Error:$(tput sgr 0) nemitavanim download konim proxy-multi.conf az server haye telegram"
fi
#Setup mtconfig.conf
echo "PORT=$PORT" >mtconfig.conf
echo "CPU_CORES=$CPU_CORES" >>mtconfig.conf
echo "SECRET_ARY=(${SECRET_ARY[*]})" >>mtconfig.conf
echo "TAG=\"$TAG\"" >>mtconfig.conf
echo "CUSTOM_ARGS=\"$CUSTOM_ARGS\"" >>mtconfig.conf
echo "TLS_DOMAIN=\"$TLS_DOMAIN\"" >>mtconfig.conf
echo "HAVE_NAT=\"$HAVE_NAT\"" >>mtconfig.conf
echo "PUBLIC_IP=\"$PUBLIC_IP\"" >>mtconfig.conf
echo "PRIVATE_IP=\"$PRIVATE_IP\"" >>mtconfig.conf
#Setup firewall
echo "tanzimate ghavanine firewall"
if [[ $distro =~ "CentOS" ]]; then
	SETFIREWALL=true
	if ! yum -q list installed firewalld &>/dev/null; then
		echo ""
		if [ "$AUTO" = true ]; then
			OPTION="y"
		else
			read -r -p "benazar \"firewalld\" bar rooye server shoma nasb nist, mayelid an ra nasb konid?(y/n) " -e -i "y" OPTION
		fi
		case $OPTION in
		"y" | "Y")
			yum -y install firewalld
			systemctl enable firewalld
			;;
		*)
			SETFIREWALL=false
			;;
		esac
	fi
	if [ "$SETFIREWALL" = true ]; then
		systemctl start firewalld
		firewall-cmd --zone=public --add-port="$PORT"/tcp
		firewall-cmd --runtime-to-permanent
	fi
elif [[ $distro =~ "Ubuntu" ]]; then
	if dpkg --get-selections | grep -q "^ufw[[:space:]]*install$" >/dev/null; then
		ufw allow "$PORT"/tcp
	else
		if [ "$AUTO" = true ]; then
			OPTION="y"
		else
			echo
			read -r -p "benazar \"firewalld\" bar rooye server shoma nasb nist, mayelid an ra nasb konid?(y/n) " -e -i "y" OPTION
		fi
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
	if ! [ "$(sysctl -n net.ipv4.tcp_congestion_control)" = "bbr" ] && { [[ $(lsb_release -r -s) =~ "20" ]] || [[ $(lsb_release -r -s) =~ "19" ]] || [[ $(lsb_release -r -s) =~ "18" ]]; }; then
		if [ "$AUTO" != true ]; then
			echo
			read -r -p "Aya mayel be estefade az BBR hastid? BBR be shoma komak mikonad proxy sari tar faal shavad.(y/n) " -e -i "y" ENABLE_BBR
		fi
		case $ENABLE_BBR in
		"y" | "Y")
			echo 'net.core.default_qdisc=fq' | tee -a /etc/sysctl.conf
			echo 'net.ipv4.tcp_congestion_control=bbr' | tee -a /etc/sysctl.conf
			sysctl -p
			;;
		esac
	fi
elif [[ $distro =~ "Debian" ]]; then
	apt-get install -y iptables iptables-persistent
	iptables -A INPUT -p tcp --dport "$PORT" --jump ACCEPT
	iptables-save >/etc/iptables/rules.v4
fi
#Setup service files
cd /etc/systemd/system || exit 2
GenerateService
echo "$SERVICE_STR" >MTProxy.service
systemctl daemon-reload
systemctl start MTProxy
systemctl is-active --quiet MTProxy #Check if service is active
SERVICE_STATUS=$?
if [ $SERVICE_STATUS -ne 0 ]; then
	echo "$(tput setaf 3)Warning: $(tput sgr 0)Sakhtar be nazar salem ast amma proxy kar nemikonad."
	echo "Check konid vaziat ra ba \"systemctl status MTProxy\""
fi
systemctl enable MTProxy
#Setup cornjob
if [ "$ENABLE_UPDATER" = "y" ] || [ "$ENABLE_UPDATER" = "Y" ]; then
	echo '#!/bin/bash
systemctl stop MTProxy
cd /opt/MTProxy/objs/bin
curl -s https://core.telegram.org/getProxySecret -o proxy-secret1
STATUS_SECRET=$?
if [ $STATUS_SECRET -eq 0 ]; then
  cp proxy-secret1 proxy-secret
fi
rm proxy-secret1
curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf1
STATUS_CONF=$?
if [ $STATUS_CONF -eq 0 ]; then
  cp proxy-multi.conf1 proxy-multi.conf
fi
rm proxy-multi.conf1
systemctl start MTProxy
echo "Updater runned at $(date). Exit codes of getProxySecret and getProxyConfig are $STATUS_SECRET and $STATUS_CONF" >> updater.log' >/opt/MTProxy/objs/bin/updater.sh
	echo "" >>/etc/crontab
	echo "0 0 * * * root cd /opt/MTProxy/objs/bin && bash updater.sh" >>/etc/crontab
	if [[ $distro =~ "CentOS" ]]; then
		systemctl restart crond
	elif [[ $distro =~ "Ubuntu" ]] || [[ $distro =~ "Debian" ]]; then
		systemctl restart cron
	fi
fi
#Show proxy links
tput setaf 3
printf "%$(tput cols)s" | tr ' ' '#'
tput sgr 0
echo "In linke proxy shoma ast:"
PUBLIC_IP="$(curl https://api.ipify.org -sS)"
CURL_EXIT_STATUS=$?
[ $CURL_EXIT_STATUS -ne 0 ] && PUBLIC_IP="YOUR_IP"
HEX_DOMAIN=$(printf "%s" "$TLS_DOMAIN" | xxd -pu)
HEX_DOMAIN="$(echo $HEX_DOMAIN | tr '[A-Z]' '[a-z]')"
for i in "${SECRET_ARY[@]}"; do
	if [ -z "$TLS_DOMAIN" ]; then
		echo "tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=dd$i"
	else
		echo "tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=ee$i$HEX_DOMAIN"
	fi
done
