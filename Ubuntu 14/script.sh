#disable ctrl-alt-delete
#sudo systemctl mask ctrl-alt-del.target
#sudo systemctl daemon-reload


######################
#   UBUNTU
######################


#colors
r="\033[0;31m"
y="\033[1;33m"
g="\033[0;32m"
em="\033[3m"
nc="\033[0m"

#banner
banner="
   _____           _ __  __        _____           _       __
  / ___/____ ___  (_) /_/ /___  __/ ___/__________(_)___  / /_
  \\__ \\/ __ \`__ \\/ / __/ __/ / / /\\__ \\/ ___/ ___/ / __ \\/ __/
 ___/ / / / / / / / /_/ /_/ /_/ /___/ / /__/ /  / / /_/ / /_
/____/_/ /_/ /_/_/\\__/\\__/\\__, //____/\\___/_/  /_/ .___/\\__/
                         /____/                 /_/  v1.5 ${em}${y}Ubuntu${g}
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
	echo "${g}6    ${r}Remove FTP service"
	echo "${g}7    ${r}Run Software Update"
	echo "${g}8    ${r}Open Software & Updates (Set 'check for updates' to Daily)"
	echo "${g}9    ${r}Remove Custom Packages"
	echo "${g}10   ${r}Remove User(s)"
	echo "${g}11   ${r}Give User(s) administrator perms"
	echo "${g}12   ${r}Take User(s) administrator perms"
	echo "${g}13   ${r}Change User(s) password"
  echo "${g}14   ${r}Edit PAM file(s)"
	echo "${g}15   ${r}Reboot"
	echo "${g}16   ${r}Exit Script"
  echo "${g}17   ${r}Show Resources${nc}"
	echo "${g}18   ${r}View all manually installed packages${nc}"





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
		#remove ftp
		echo "Remove FTP service? (y/n)"
		read ftpService
		if [ $ftpService = "y" ]
		then
			sudo apt-get remove pure-ftpd
		fi

	elif [ $input = "7" ]
	then
		#install updates
		echo "Update? (y/n)"
		read update
		if [ $update = "y" ]
		then
			sudo update-manager
		fi

	elif [ $input = "8" ]
	then
		software-properties-gtk --open-tab 2

	elif [ $input = "9" ]
	then
		#remove custom packages
		echo "Remove custom packages? (y/n)"
		read rmCustomPkg
		if [ $rmCustomPkg ]
		then
			rmOtherPkg="y"
			while [ $rmOtherPkg = "y" ]; do
				echo "Enter the package name:"
				read pkgName
				echo "Removing $pkgName"
				sudo apt-get remove $pkgName
				echo "Remove another package? (y/n)"
				read rmOtherPkg
			done
		fi

	elif [ $input = "10" ]
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

	elif [ $input = "11" ]
	then
		#give users admin perms
		echo "Enter each user on a separate line. Type 'exit' to go back."
		read user
		while [ $user != "exit" ]; do
			sudo usermod -aG sudo $user
			read user
		done

	elif [ $input = "12" ]
	then
		#take users admin perms
		echo "Enter each user on a separate line. Type 'exit' to go back."
		read user
		while [ $user != "exit" ]; do
			sudo deluser $user sudo
			read user
		done

	elif [ $input = "13" ]
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


  elif [ $input = "14" ]
  then
    #edit PAM files
    echo "Type the number of the file you want to edit."
    echo "Type 'exit' to go back."
    echo "${g}1   ${r}Open All"
    echo "${g}2   ${r}Password File"
    echo "${g}3   ${r}Password History"
    echo "${g}4   ${r}Account Policy"
		echo "${g}5   ${r}Install libpam-cracklib (DO THIS BEFORE EDITING PASSWORD POLICIES)"

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
			elif [ $input = "5" ]
			then
				echo "Installing libpam-cracklib"
				sudo apt-get install libpam-cracklib
				echo "Installed libpam-cracklib"
      fi
    done


	elif [ $input = "15" ]
	then
		#restart computer
		echo "Are you sure you want to restart the computer/image? (y/n)"
		read restart
		if [ $restart = "y" ]
		then
			sudo reboot
		fi

	elif [ $input = "16" ]
	then
		#exit message
		clear
		echo "${g}Have a nice day!"
		echo "${r}Don't forget to re-read the guidelines and rules for this round!${nc}"
		break
  elif [ $input = "17" ]
  then
    #show Resources
    echo "${y}Enter the number to open the desired url."
    echo "Type 'exit' to go back."
    echo "${g}1   ${r}Usermod docs. - used to modify user accounts"
    echo "${g}2   ${r}"
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
      fi
    done
	elif [ $input = "18" ]
	then
		#show manually installed packages
		echo "syntax: comm -linetoignore file1 file2"
		echo "compares files line by line"
		echo "comm -23 <(apt-mark showmanual | sort -u) <(gzip -dc /var/log/installer/initial-status.gz | sed -n 's/^Package: //p' | sort -u)"
	fi
done
