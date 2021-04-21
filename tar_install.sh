#!/bin/sh
#
# Install script file for Perle TruePort Linux driver
# 
# Copyright (c) 2003-2009  Perle Systems Limited
#
# In principle, this should do the build-and-install. However, normally
# users are told to do the make, make install, etc.  steps separately
# This allows an operator to diagnose and solve problems in one of the
# steps more easily than if it's one "black box" of commands here. If
# you encounter problems, we recommend you follow these steps in this
# script one-by-one. 
#
###########################################################################################


###########################################################################################
#
#	This routine checks the details of any current installation of openssl.

check_openssl()
{
	rm -f testopenssl
	make testopenssl
	result=$?
	if [ "$result" != "0" ]; then
		PROBLEM_TEXT=1
	fi
	
	if [ "$NEED_SSL" = "" ]; then
	  CHECK_LIBS=yes
	  export CHECK_LIBS
	  rm -f testopenssl
	  make testopenssl
	  result=$?
	  if [ "$result" != "0" ]; then
		PROBLEM_TEXT=2
	  else
		./testopenssl
		result=$?
		if [ "$result" = "2" ]; then
		  PROBLEM_TEXT=3
		  
		else if [ "$result" = "3" ]; then
		  PROBLEM_TEXT=4

		else if [ "$result" = "0" ]; then
			PROBLEM_TEXT=0
		else  
		  PROBLEM_TEXT=5
		fi
		fi
		fi
	  fi
    fi

	return
}


###########################################################################################

# START of script.
KERNEL_VER_A=`uname -r | awk -F. '{printf "%d", $1}'`
KERNEL_VER_B=`uname -r | awk -F. '{printf "%d", $2}'`

if [ "$KERNEL_VER_A" -lt 3 ] && [ "$KERNEL_VER_B" -le 4 ] ; then
	 echo "ERROR: This version of TruePort does not support Linux kernel"
	 echo "       versions less then 2.6.0. TruePort versions 6.3.x"
	 echo "       supports Linux kernel versions 2.2.19 or higher and 2.4.x. "
 	 echo
	 exit 0
fi

DONE="not done"
while [ "$DONE" = "not done" ]; do
  echo 
  echo -n "Install SSL/TLS feature? (yes or no ): "
  read answer
  case "$answer" in
	yes|y)	SSL=1
			DONE=done
			;;

	no|n)	DONE="done"
			;;
		
	*)		;;	
  esac
done
if [ "$SSL" = "1" ]; then
	# if check_openssl fails, display error message and exit install
	check_openssl	#check openssl function
	if [ "$PROBLEM_TEXT" != "0" ]; then
		./test_local_openssl.sh $PROBLEM_TEXT
		echo "The install was not completed"
		exit 255
	fi
fi

DONE="not done"
MAXINSTPORTS=256
MAX_PORTS=256000
while [ "$DONE" = "not done" ]; do
	echo 
	echo -n "Please enter the maximum number of ports to install [${MAXINSTPORTS}] "
	read answer
	if [ "$answer" = "" ]; then
		DONE=done
	elif [ $answer -le $MAX_PORTS ] && [ $answer -ge "1" ]; then
		MAXINSTPORTS=$answer 
		DONE=done
	else
		echo " "
		echo "Error:  Please enter a valid number in the range 1 to $MAX_PORTS"
		echo " "
		continue
	fi
done

# Generate header file containing #define for MAX_DEVICES
echo "// TruePort Driver auto-generated header file, do not modify" >tp-autogen.h
echo "#define MAXINSTPORTS $MAXINSTPORTS" >>tp-autogen.h
SUB_MAX_TTY=`expr $MAXINSTPORTS - 1`
mv addports addports.save
sed -e s/MAX_TTY=.*/MAX_TTY=$SUB_MAX_TTY/ addports.save > addports


# determine architecture using uname -m
# need special config flag for application if on PPC64 or SPARC64
MACHINE="`uname -m`"

export SSL
export MACHINE
export MAXINSTPORTS

# If this is an rpm build, then set variables in files and exit to let rpm 
#  control the rest of the build process.

if [ "$1" = "rpm_build" ]; then
	echo $SSL > ./ssl
	echo $MACHINE > ./machine
	echo $MAXINSTPORTS > /tmp/maxinstports
	exit 0
fi

###########################################################################################

make clean
make
if [ "$?" != "0" ]; then
	exit 2
fi
make install
depmod -a 

./postinstall.sh

echo install complete

