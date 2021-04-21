#!/bin/bash
#

PROBLEM_TEXT=$1

if [ "$PROBLEM_TEXT" = "1" ]; then
	echo ""
	echo ""
	echo "******************************************************************************"
	echo "* Unable to locate the OpenSSL headers!"
	echo "*"
	echo "* The Perle TruePort driver requires the OpenSSL layer."
	echo "* Please install openssl on your system with a version of 0.9.7 or later."
	echo "*"
else if [ "$PROBLEM_TEXT" = "2" ]; then
	echo ""
	echo ""
	echo "******************************************************************************"
	echo "* Unable to locate the OpenSSL libcrypto library!"
	echo "*"
	echo "* The Perle TruePort driver requires the OpenSSL libcrypto library."
	echo "* Please install openssl on your system with a version of 0.9.7 or later."
	echo "*"
else if [ "$PROBLEM_TEXT" = "3" ]; then
	echo ""
	echo ""
	echo "******************************************************************************"
	echo "* Your OpenSSL headers do not match your library!"
	echo "*"
	echo "* The Perle TruePort driver requires the OpenSSL header version to match"
	echo "* the OpenSSL library version installed on your system."
	echo "* Please reinstall openssl on your system with a version of 0.9.7 or later."
	echo "*"
else if [ "$PROBLEM_TEXT" = "4" ]; then
	echo ""
	echo ""
	echo "******************************************************************************"
	echo "* Your OpenSSL version is not current enough!"
	echo "*"
	echo "* The Perle TruePort driver requires the OpenSSL version to be at least 0.9.7"
	echo "* Please reinstall openssl on your system with a version of 0.9.7 or later."
	echo "*"
else if [ "$PROBLEM_TEXT" = "5" ]; then
	echo ""
	echo ""
	echo "******************************************************************************"
	echo "* The TruePort software cannot use the existing version of OpenSSL!"
	echo "*"
	echo "* The Perle TruePort driver requires the OpenSSL software"
	echo "* Please install openssl on your system with a version of 0.9.7 or later."
	echo "*"
fi
fi
fi
fi
fi

#  Cannot continue with the install until proper version of openssl is installed.
exit 255


