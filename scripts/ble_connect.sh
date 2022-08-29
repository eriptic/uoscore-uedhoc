#!/bin/bash
# Copyright (c) 2022 Eriptic Technologies. See the COPYRIGHT
# file at the top-level directory of this distribution.

# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

# Run this script on a linux host (tested on Debian 11) in order to connect a BLE board running IPv6 over BLE.

# This script is based on the configuration example https://docs.zephyrproject.org/latest/samples/bluetooth/ipsp/README.html


ROOT_UID=0		# Only users with $UID 0 have root privileges
E_NOTROOT=87		# Non-root exit error


# Run this script as root
if [ "$EUID" -ne 0 ]
then
	echo "Must be root to run this script."
	exit $E_NOTROOT
fi



# Create Help menu message
version="BLE connect helper script 0.1.0 (2022)"
argument[0]="\t-d <device name>\tSpecify the name of the device to which the router will connect"
argument[1]="\t-h\t\t\tPrint Help (this message) and exit"


CON=false


function connect(){

	while true
	do
		# Load 6LoWPAN module.
		modprobe bluetooth_6lowpan

		# Enable the bluetooth 6lowpan module.
		echo 1 > /sys/kernel/debug/bluetooth/6lowpan_enable

		# Look for available HCI devices. Use for debug only
		# hciconfig		
		
		#scan for a device
		device=''
		while [ -z "$device" ]
		do
			echo "[$(date +"%T")] scanning for devices"
			# Reset HCI device
			invoke-rc.d bluetooth restart	
			#systemctl disable bluetooth.service 	
			#systemctl enable bluetooth.service

			hciconfig hci0 reset

			# scan	
			device=$(timeout 1s stdbuf -oL hcitool lescan | grep "$1")	
		done

		# Set space as the delimiter
		IFS=' '
		#Read the split words into an array based on space delimiter
		read -a mac <<< "$device"
		echo "connect to $device"
		echo "connect $mac 2 " > /sys/kernel/debug/bluetooth/6lowpan_control
		sleep 1
		
		#make sure we select short connection events
		#min connection interval 6*1.25ms = 7.5ms
		echo "6" > /sys/kernel/debug/bluetooth/hci0/conn_min_interval
		#max connection interval 7*1.25ms = 8.25ms
		echo "7" > /sys/kernel/debug/bluetooth/hci0/conn_max_interval

		#assign a static address to the bt0 interface
		ip address add 2001:db8::2/64 dev bt0


		#check if the device is disconnected 
		connected_device=$(hcitool con | grep $mac)
		read -a mac1 <<< "$connected_device"
		while [ ${mac1[2]} ]
		do
			sleep 3
			connected_device=$(hcitool con | grep $mac)
			read -a mac1 <<< "$connected_device"
			echo "[$(date +"%T")] connected with $device"
		done

		echo "device disconnected"
		CON=false

	done
}


function help(){
	# Print Help menu
	echo -e "$version\nArguments:\n";
	i=1
	for i in "${argument[@]}" ; do
		echo -e "$argument$i"
	done
}




while getopts hd: option
do
	case "${option}"
	in
		h) help ; exit ;;
		d) connect ${OPTARG};;
	esac
done