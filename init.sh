#!/bin/bash

#########################
                        #
project_root=~/Machine_Results      #    Edit this variable if your notes are somewhere else
                        #
#########################

WHITE='\033[0;37m'
RESET='\033[0m'
RED_B='\033[1;31m'
GREEN_B='\033[1;32m'
WHITE_B='\033[1;37m'
CYAN_B='\033[1;36m'

function build_tree() {

	# Performing basic checks here

	if [ ! -d $project_root ]; then

		echo -e "${CYAN_B}"
		read -p "Request: \"$project_root\" folder not found, create now? (y/n): "  -n 1 -r create
		echo -e ${WHITE}

		if [ $create == "y" ] || [ $create == "Y" ]; then

			mkdir $project_root

		elif [ $create == "n" ] || [ $create == "N" ]; then

			echo -e "${RED_B}Quitting.${RESET}\n"
			exit 0

		else
	
			echo -e "\n${RED_B}ERROR:${WHITE} invalid selection \"$create\"... \n${RED_B}QUITTING.${RESET}\n"
			exit 1
		fi
	fi

    # Ask for the platform name
    echo -e "${WHITE_B}"
    read -p "Enter the platform name (e.g., HackTheBox, TryHackMe): " PLATFORM_NAME

    # Check and create platform directory
    platform_dir=$project_root/$PLATFORM_NAME
    if [ ! -d $platform_dir ]; then
        echo -e "${GREEN_B} - creating directory for platform \"$PLATFORM_NAME\" in \"$project_root\"${RESET}"
        mkdir $platform_dir
    else
        echo -e "${CYAN_B}Platform directory \"$PLATFORM_NAME\" already exists in \"$project_root\"${RESET}"
    fi

	# This section creates the root directory of the current box

	box_home=$platform_dir/$1/

	#########################################################################
	                                                                        #
	directory_list=("nmap")       						#  Edit this list to fit your needs
	                                                                        #
	#########################################################################

	#########################################################################
	                                                                        #
	file_list=("hashes" "passwords" "users")       				#  Edit this list to fit your needs
	                                                                        #
	#########################################################################

	if [ ! -d $box_home ]; then

		echo -e "\n${GREEN_B} - creating directory \"$1\" in \"$platform_dir\""
		mkdir $box_home

		for i in ${directory_list[@]}; do
	
			echo -e "${WHITE} - creating sub-directory ${CYAN_B}$i${WHITE} in $box_home"
			mkdir $box_home$i
			sleep 0.1
		done

		for i in ${file_list[@]}; do
	
			echo -e "${WHITE} - creating file ${CYAN_B}$i${WHITE} in $box_home"
			touch $box_home$i
			sleep 0.1
		done

	echo -e "\n${CYAN_B}Done.${RESET}\n"

	else
		echo
		echo -e "${RED_B}ERROR: ${WHITE_B}directory \"$1\" already exists in \"$platform_dir\"! \n${CYAN_B}Skipping.\n${RESET}"
	fi
}


function start_nmap(){

	echo -e "${CYAN_B}>> Initiating preliminary nmap scan\n"
	echo -e "${GREEN_B}Open ports on ${WHITE_B}$1:\n${RESET}"

	OPEN_PORTS=$(echo -e "`sudo nmap $1 -p- -Pn --open -oA $box_home\"nmap/open\"|   # find open ports
			grep \"open\"`" | 					# grep for lines with open
			tee /dev/tty | 						# print list of ports and service name
			cut -d '/' -f1 |					# strip lines to get only the numbers
		       	paste -s -d "," -					# format results to nmap argument format 
		)

	echo -e "\n${CYAN_B}>> Starting enumeration of discovered services"
	echo -e "${WHITE_B}   this could take a while, sit tight!\n${RESET}"

	nmap $1 -sC -sV -p$OPEN_PORTS -q -4 -v --max-retries=1 -oA $box_home"nmap/services"  &> /dev/null
	
	echo -e "${WHITE}   - saving results in " $box_home"nmap/${RESET}"
	sleep 1

	echo -e "\n${CYAN_B}>> Scan done. Opening results for review...\n${RESET}"
	sleep 1
	
	while IFS= read -r line; do 
		echo "   $line" 
		sleep 0.1
	done < 	$box_home"nmap/services.nmap"

	echo -e "${CYAN_B}\nDone and opening sublime.${RESET}"

	sudo subl $box_home
}

function is_valid_ip() {

if [[ $1 =~ ^([0-9]{1,3}[\.]){3}([0-9]{1,3})$ ]] || [[ `dig $1 +short` ]]; then

		start_nmap $1
	else
	
		echo -e "${RED_B}Invalid IP or HostName:${WHITE_B} cannot scan '$1'!${RESET}"
		echo -e "${CYAN_B}Aborting nmap scan!${RESET}\n"
		exit 1
	fi
}

# This section checks the arguments list (Execution starts here) 

if [[ $* == "-h" ]] || [[ $* == "-help"  ]] || [[ $* == "--help" ]]; then

	echo -e "\n${GREEN_B}Usage: ${CYAN_B} $0 <box name> <optional: IP>\n${RESET}"
	exit
fi

if [ "$#" == 1 ]; then

	build_tree $1
	exit

elif [ "$#" == 2 ]; then

	build_tree $1
	is_valid_ip $2
	exit

else

	echo -e "${WHITE}"
	echo -e "${RED_B}Error: ${WHITE} missing parameters."
	echo -e "${GREEN_B}Usage: ${CYAN_B} $0 <box name> <optional: IP>\n${RESET}"
	exit 1
fi
