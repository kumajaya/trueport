# !/bin/sh
#
# Post Install script file for Perle TruePort Linux driver
# 
# Copyright (c) 2003-2009  Perle Systems Limited
#
###########################################################################################



echo "Running Post Install script..."


# determine the version of the running kernel to control next phase of install

MODPROBE_CONF=/etc/modprobe.conf
MODPROBE_CONFIG=${MODPROBE_CONF}
MODPROBE_DIR=/etc/modprobe.d
MODPROBED_NAME=trueport
MODPROBED_NAME_CONF=${MODPROBED_NAME}.conf



if ! test -f ${MODPROBE_CONF} ; then
  # if modprobe.d directory exists, then modprobe configuration file will be 
  # created there.
  if test -d ${MODPROBE_DIR} ; then
	  MODPROBE_CONFIG=${MODPROBE_DIR}/${MODPROBED_NAME_CONF}
  else
  	#create modprobe.conf file
	echo > ${MODPROBE_CONFIG}
  fi
else
	# if /etc/modprobe.conf files is automatically generated
	# then use  MODPROBE_DIR
	if grep -q "automatically generated" ${MODPROBE_CONFIG} ; then
		MODPROBE_CONFIG=${MODPROBE_DIR}/${MODPROBED_NAME_CONF}
	fi
fi

if [ "${MODPROBE_CONFIG}" = "${MODPROBE_CONF}" ]; then
	#remove any old config data
	mv ${MODPROBE_CONFIG} ${MODPROBE_CONFIG}.tp.save
	sed -e "/options ptyx/d" \
		-e "/alias char-major-62 ptyx/d"									\
		-e "/# ptyx/d" ${MODPROBE_CONFIG}.tp.save > ${MODPROBE_CONFIG}
	rm ${MODPROBE_CONFIG}.tp.save
fi
#remove any existing modprobe.d files for this product regardless if we are now using modprobe.conf or not.
rm -f /etc/modprobe.d/${MODPROBED_NAME_CONF} > /dev/null 2>&1
# remove any legacy file from version 6.3
rm -f /etc/modprobe.d/${MODPROBED_NAME} > /dev/null 2>&1
#add new config data.
echo "Updating ${MODPROBE_CONFIG}"
echo "# ptyx module support" >> ${MODPROBE_CONFIG}
echo "alias char-major-62 ptyx" >> ${MODPROBE_CONFIG}
echo "options ptyx max_installed_ports=${MAXINSTPORTS}" >> ${MODPROBE_CONFIG}
if [ -x /sbin/depmod -a -e /lib/modules/`/bin/uname -r`/modules.dep ] ; then
	/sbin/depmod -a 
fi

# Let the system know we are installing our startup scripts
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
	$CHKCONFIG_BIN --add trueport
else
	echo "TruePort startup scripts must be manually added"
fi




# Force dependency checks
if [ -e /sbin/depmod ]
then
	/sbin/depmod -a
fi

/etc/init.d/trueport restart

echo

