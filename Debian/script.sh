#disable ctrl-alt-delete
#sudo systemctl mask ctrl-alt-del.target
#sudo systemctl daemon-reload


######################
#   DEBIAN
######################


#colors
r="\033[0;31m"
y="\033[1;33m"
g="\033[0;32m"
nc="\033[0m"

#banner
banner="
   _____           _ __  __        _____           _       __
  / ___/____ ___  (_) /_/ /___  __/ ___/__________(_)___  / /_
  \\__ \\/ __ \`__ \\/ / __/ __/ / / /\\__ \\/ ___/ ___/ / __ \\/ __/
 ___/ / / / / / / / /_/ /_/ /_/ /___/ / /__/ /  / / /_/ / /_
/____/_/ /_/ /_/_/\\__/\\__/\\__, //____/\\___/_/  /_/ .___/\\__/
                         /____/                 /_/     v1.0
"

#loop
input="0"
while [ $input != "14" ]; do

	clear

	echo "${g}${banner}"

	#commands
	echo "${y}Type the corresponding number to run the desired function."
	echo "${g}1    ${r}Enable fire wall"
	echo "${g}2    ${r}Allow/Disable outgoing connections"
	echo "${g}3    ${r}Allow/Disable incoming connections"
	echo "${g}4    ${r}Allow/Disable specific ports for incoming connections"
	echo "${g}5    ${r}Disable Guest Account"
	echo "${g}6    ${r}Preconfigured Commands"
	echo "${g}7    ${r}Run Software Update"
	echo "${g}8    ${r}Open Software & Updates (Set 'check for updates' to Daily)"
	echo "${g}9    ${r}Remove Custom Packages"
	echo "${g}10   ${r}Add Custom Packages"
	echo "${g}11   ${r}Remove User(s)"
	echo "${g}12   ${r}Give User(s) administrator perms"
	echo "${g}13   ${r}Take User(s) administrator perms"
	echo "${g}14   ${r}Change User(s) password"
  echo "${g}15   ${r}Edit PAM file(s)"
	echo "${g}16   ${r}Reboot"
	echo "${g}17   ${r}Exit Script"
  echo "${g}18   ${r}Show Resources${nc}"





  read input
	if [ -z "$input" ]
	then
		input="0"
	fi

	if [ $input = "1" ]
	then
		#enable fire-wall
		echo "Enabling fire wall."
		sudo ufw enable

	elif [ $input = "2" ]
	then
		#Allow/disable outgoing connections
		echo "Allow outgoing connections? (y/n)"
		read outConn
		if [ $outConn = "n" ]
		then
			sudo ufw default deny outgoing
		else
			sudo ufw default allow outgoing
		fi

	elif [ $input = "3" ]
	then
		#Allow/disable incoming connections
		echo "Allow incoming connections? (y/n)"
		read inConn
		if [ $inConn = "y" ]
		then
			sudo ufw default allow incoming
		else
			sudo ufw default deny incoming
		fi

	elif [ $input = "4" ]
	then
		#Allow/disable ports for incoming connections
		echo "Allow(a) or disable(d) ports for incoming connections? (a/d)"
		read allowInPorts
		if [ $allowInPorts = "a" ]
		then
			echo "Type each port you want to allow on separate lines. Type 'exit' to stop entering ports."
			read port
			while [ $port != "exit" ]; do
				sudo ufw allow $port
				read port
			done
		fi

  elif [ $input = "5" ]
  then
    sudo echo 'allow-guest=false' >> /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
		echo "Guest account disabled."
		echo "Restart computer/image to apply changes? (y/n)"
		read restart
		if [ $restart = "y" ]
		then
			sudo reboot		
		fi

	elif [ $input = "6" ]
	then
		#preconfigured commands
		echo "${y}Select the desired command by it's number. Type 'Exit' to go back."
		#echo "${g}1   ${r}Run All"
		echo "\n${y}FTP"
		echo "${g}2   ${r}Remove FTP service"
		echo "\n${y}SSH"
		echo "${g}3   ${r}Install OpenSSH Server"
		echo "${g}4   ${r}Start OpenSSH Server"
		echo "${g}5   ${r}Stop OpenSSH Server"
		echo "${g}6   ${r}Enable OpenSSH Server from startup"
		echo "${g}7   ${r}Disable OpenSSH Server from startup"
		echo "${g}8   ${r}Check Status of OpenSSH Server"
		echo "${g}9   ${r}Change SSH Port"
		echo "${g}10  ${r}Allow/Disable Remote Root Login"
		echo "\n${y}Services"
		echo "${g}11   ${r}Show all services"
		echo "\n${y}IP Tables"
		echo "${g}12   ${r}Force SYN packets check"
		echo "${g}13   ${r}Drop XMAS packets"
		echo "${g}14   ${r}Drop null packets"
		echo "${g}15   ${r}Drop incoming packets with fragments"
		echo "\n${y}Apache2"
		echo "${g}16   ${r}Remove Apache2"
		echo "${nc}"
		
		input="0"
		while [ $input != "exit" ]; do
			read input
			if [ -z "$input" ]
    	then
    		input="0"
    	fi
		
			if [ $input = "1" ]
			then
				sudo apt-get remove pure-ftpd
			elif [ $input = "2" ]
			then
				#Remove FTP
				sudo apt-get remove pure-ftpd
			elif [ $input = "3" ]
			then
				#Install SSH
				sudo apt-get install openssh-server
			elif [ $input = "4" ]
			then
				#Start SSH
				sudo systemctl start ssh
			elif [ $input = "5" ]
			then
				#Stop SSH
				sudo systemctl stop ssh
			elif [ $input = "6" ]
			then
				#Enable SSH
				sudo systemctl enable ssh
			elif [ $input = "7" ]
			then
				#Disable SSH
				sudo systemctl disable ssh
			elif [ $input = "8" ]
			then
				#SSH Status
				sudo systemctl status ssh
			elif [ $input = "9" ]
			then
				#SSH set port
				echo "Type the port you want SSH to use, or type 'exit' to go back."
				read port
				if [ $port != "exit" ]
				then
					sudo echo "Port ${port}" >> /etc/ssh/sshd_config
				fi
			elif [ $input = "10" ]
			then
				#SSH disable remote root login
				echo "Disable remote root login? (y/n)"
				read remoteLogin
				if [ $remoteLogin = "y" ]
				then
					sudo echo "PermitRootLogin no"
				fi
				
			elif [ $input = "11" ]
			then
				#show all services
				sudo systemctl list-unit-files --type=service
			elif [ $input = "12" ]
			then
				#Force SYN packets check
				sudo iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
			elif [ $input = "13" ]
			then
				#Drop XMAS packets
				sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
			elif [ $input = "14" ]
			then
				#Drop null packets
				sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
			elif [ $input = "15" ]
			then
				#Drop incoming packets with fragments
				sudo iptables -A INPUT -f -j DROP
			elif [ $input = "16" ]
			then
				#Remove Apache2
				sudo apt-get remove apache2
			fi
		done
		
	elif [ $input = "7" ]
	then
		#install updates
		echo "Update? (y/n)"
		read update
		if [ $update = "y" ]
		then
			sudo apt-get update && apt-get upgrade
			sudo apt-get -f install
			sudo apt-get -u dist-upgrade
		fi

	elif [ $input = "8" ]
	then
		software-properties-gtk --open-tab 2

	elif [ $input = "9" ]
	then
		#remove custom packages
		echo "Remove custom packages? (y/n)"
		read rmCustomPkg
		if [ $rmCustomPkg = "y" ]
		then
			rmOtherPkg="y"
			while [ $rmOtherPkg = "y" ]; do
				echo "Enter the package name:"
				read pkgName
				echo "Do you want to purge the package? (remove config and/or data files) (y/n)"
				read purge
				echo "Do you want to remove the package's dependencies? (y/n)"
				read rmDpncy
				echo "Removing $pkgName"
				
				if [ $purge = "y" ]
				then
					if [ $rmDpncy = "y" ]
					then
						sudo apt-get purge --auto-remove $pkgName
					else
						sudo apt-get purge $pkgName
					fi
				elif [ $rmDpncy = "y" ]
				then
					sudo apt-get remove --auto-remove $pkgName
				else
					sudo apt-get remove $pkgName
				fi
				echo "Package removed."
				echo "Remove another package? (y/n)"
				read rmOtherPkg
			done
		fi

	elif [ $input = "10" ]
	then
		#add custom package
		echo "Type the name of the package to add."
		echo "Type 'exit' to go back."
		read pkgName
		sudo apt-get install $pkgName


	elif [ $input = "11" ]
	then
		#remove users
		rmOtherUsr="y"
		while [ $rmOtherUsr = "y" ]; do
			echo "Input the username:"
			read usr
			echo "Delete all user's files? (y/n)"
			read delAllUsrFiles
			if [ $delAllUsrFiles = "y" ]
			then
			  sudo userdel -r $usr
			else
			  sudo userdel $usr
			fi
			echo "$usr was deleted."
			echo "Remove another user? (y/n)"
			read rmOtherUsr
		done

	elif [ $input = "12" ]
	then
		#give users admin perms
		echo "Enter each user on a separate line. Type 'exit' to go back."
		read user
		while [ $user != "exit" ]; do
			sudo usermod -aG sudo $user
			read user
		done

	elif [ $input = "13" ]
	then
		#take users admin perms
		echo "Enter each user on a separate line. Type 'exit' to go back."
		read user
		while [ $user != "exit" ]; do
			sudo deluser $user sudo
			read user
		done

	elif [ $input = "14" ]
	then
		#change users' passwords
		echo "Type 'exit' to go back and cancel the current user you are editing."
		username=" "
		password=" "
		n="1"
    while [ $n = "1" ]; do
      echo "Username:"
  		read username
      if [ $username = "exit" ]
      then
        break
      fi

      echo "Password:"
      read password
      if [ $password = "exit" ]
      then
        break
      fi

      sudo usermod --password $password $username
    done


  elif [ $input = "15" ]
  then
    #edit PAM files
    echo "Type the number of the file you want to edit."
    echo "Type 'exit' to go back."
    echo "${g}1   ${r}Open All"
    echo "${g}2   ${r}Password File"
    echo "${g}3   ${r}Password History"
    echo "${g}4   ${r}Account Policy"

    while [ $input != "exit" ]; do
      read input
      if [ -z "$input" ]
    	then
    		input="0"
    	fi
      if [ $input = "1" ]
      then
        gedit /etc/pam.d/common-password
        gedit /etc/login.defs
        gedit /etc/pam.d/common-auth
      elif [ $input = "2" ]
      then
        echo "${nc}To enforce password history of 5:
Add ${y}“remember=5”${nc} to the end of the line that has ${y}“pam_unix.so”${nc} in it."
        echo ""
        echo "${r}To enforce Password length of 8:
Add ${y}“minlen=8”${r} to the end of the line that has ${y}“pam_unix.so”${r} in it"
        echo ""
        echo "${nc}To enforce password complexity with one of each type of character:
*Add ${y}“ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1”${nc} to the end of the line with “pam_cracklib.so” in it.**
*ucredit = upper case, lcredit=lower case, dcredit = number and ocredit = symbol
**cracklib may need to be installed before enforcing password complexity"
        gedit /etc/pam.d/common-password
      elif [ $input = "3" ]
      then
        echo "${y}Search for: PASS_MAX_AGE"
        echo "${r}Set ${g}PASS_MAX_DAYS ${r}to ${g}90"
        echo "${r}Set ${g}PASS_MIN_DAYS ${r}to ${g}10"
        echo "${r}Set ${g}PASS_WARN_AGE ${r}to ${g}7"
        gedit /etc/login.defs
      elif [ $input = "4" ]
      then
        echo "Add to end of file:"
        echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800"
        echo "----------------------------^^^^^^------------^^^^^^^^^^^^^^^^"
        echo "                      Sets number of failed     Sets lockout"
        echo "                        login attempts.          duration(s)"
        echo ""
        gedit /etc/pam.d/common-auth
      fi
    done


	elif [ $input = "16" ]
	then
		#restart computer
		echo "Are you sure you want to restart the computer/image? (y/n)"
		read restart
		if [ $restart = "y" ]
		then
			sudo reboot
		fi

	elif [ $input = "17" ]
	then
		#exit message
		clear
		echo "${g}Have a nice day!"
		echo "${r}Don't forget to re-read the guidelines and rules for this round!${nc}"
		break
  elif [ $input = "18" ]
  then
    #show Resources
    echo "${y}Enter the number to open the desired url."
    echo "Type 'exit' to go back."
    echo "${g}1   ${r}Usermod docs. - used to modify user accounts"
    echo "${g}2   ${r}Services systemctl"
    echo "${nc}"
    while [ $input != "exit" ]; do
      read input
      if [ -z "$input" ]
    	then
    		input="0"
    	fi
      if [ $input = "1" ]
      then
        x-www-browser http://manpages.ubuntu.com/manpages/cosmic/man8/usermod.8.html
	elif [ $input = "2" ]
	then
		x-www-browser https://askubuntu.com/questions/218/command-to-list-services-that-start-on-startup#6649
      fi
    done
	fi
done