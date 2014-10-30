#!/bin/bash
export otr_version=`./check-otr-version.sh`

if [ "${otr_version}" == '4' ]
then
    echo "Found local version of libotr: ${otr_version}"
    make module
    exit
fi

if [ "${otr_version}" == '3' ]
then
    echo "module 'otr4' requires at least libotr 4.0.0 or above on the system."
    exit
fi

#if we reached here libotr was not found.
echo "libotr could not be located on your system."
echo "On Debian/Ubuntu you can install it with the following command:"
echo "  sudo apt-get install libotr5 libotr5-dev"
echo ""
echo "On MacOS 10.x you can install it using brew:"
echo "  brew install libotr"
