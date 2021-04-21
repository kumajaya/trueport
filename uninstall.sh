# !/bin/sh
#
# Unistall script file for Perle TruePort Linux driver
# 
# Copyright (c) 2003-2009  Perle Systems Limited
#
###########################################################################################

	
# determine the version of the running kernel to control next phase of install
KERNEL_VER_B=`uname -r | awk -F. '{printf "%d", $2}'`

MODPROBE_CONF=/etc/modprobe.conf
MODPROBE_CONFIG=${MODPROBE_CONF}
MODPROBE_DIR=/etc/modprobe.d
MODPROBED_NAME=trueport
MODPROBED_NAME_CONF=${MODPROBED_NAME}.conf
DRIVER_MODULE=ptyx.ko


if ! test -f ${MODPROBE_CONFIG} ; then
  if test -d ${MODPROBE_DIR} ; then
	  MODPROBE_CONFIG=${MODPROBE_DIR}/${MODPROBED_NAME_CONF}
  fi
fi
# if /etc/modules.conf or /etc/modprobe.conf files is automatically generated
# then use  MODPROBE_DIR
if grep -q "automatically generated" ${MODPROBE_CONFIG} ; then
	MODPROBE_CONFIG=${MODPROBE_DIR}/${MODPROBED_NAME_CONF}
fi

bindir=/usr/bin
LEVEL="2 3 5"
base=$(if [ -d /etc/init.d/rc2.d ] ; then echo /etc/init.d ; elif [ -d /etc/rc2.d ] ; then  echo /etc/ ; else echo UNKONWN  ; fi)

/etc/init.d/trueport stop

if test ! -w ${MODPROBE_CONFIG}; then
	echo "Cannot find ${MODPROBE_CONFIG}. Nothing to remove from ${MODPROBE_CONFIG}"
else
	if [ "${MODPROBE_CONFIG}" = "${MODPROBE_CONF}" ]; then
		echo Removing lines from ${MODPROBE_CONFIG}
		mv ${MODPROBE_CONFIG} ${MODPROBE_CONFIG}.tp.save
		sed -e "/options ptyx/d" \
			-e "/alias char-major-62 ptyx/d"									\
			-e "/# ptyx/d" ${MODPROBE_CONFIG}.tp.save > ${MODPROBE_CONFIG}
		#cleanup
		rm ${MODPROBE_CONFIG}.tp.save 
	else
		#just delete modprobe.d files for trueport. no need to parse.
		echo Deleting ${MODPROBE_CONFIG} .
		rm -f ${MODPROBE_CONFIG} > /dev/null 2>&1
		#this is to clean up file from version 6.3.
		rm -f /etc/modprobe.d/${MODPROBED_NAME} > /dev/null 2>&1
	fi
fi

rm -f  /lib/modules/`uname -r`/misc/${DRIVER_MODULE}
rm -f  /usr/bin/addports
rm -f  /usr/bin/cleanports
rm -f  /usr/bin/trueportd
rm -f  /usr/bin/tpadm
rm -fR  /usr/share/doc/trueport



rm -f /etc/trueport/tplogin
rm -f /etc/trueport/addlogins
rm -f /etc/trueport/rmlogins
rm -f /etc/trueport/swirl
cp -f /etc/trueport/config.tp /etc/trueport/config.tp.tarsave
cp -f /etc/trueport/sslcfg.tp /etc/trueport/sslcfg.tp.tarsave
cp -f /etc/trueport/pktfwdcfg.tp /etc/trueport/pktfwdcfg.tp.tarsave
rm -f /etc/trueport/config.tp 
rm -f /etc/trueport/sslcfg.tp 
rm -f /etc/trueport/pktfwdcfg.tp 
rm -f /etc/trueport/postinstall.sh
rm -f /etc/trueport/uninstall.sh


# Let the system know we are removing our starup scripts in /
CHKCONFIG_BIN=""
if [ -x /sbin/chkconfig ]
then 
	CHKCONFIG_BIN="/sbin/chkconfig"
fi
if [ -x /usr/sbin/chkconfig ]
then
	CHKCONFIG_BIN="/usr/sbin/chkconfig"
fi
if [ $CHKCONFIG_BIN ]
then
	$CHKCONFIG_BIN --del trueport
else
	echo "TruePort startup scripts must be manually removed"
fi



echo Removing done
