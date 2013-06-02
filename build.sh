#!/bin/bash
export otr_version=`./check-otr-version.sh`

if [ "${otr_version}" == '' ]
then
    echo "No libotr found on the system."
    echo "On Debian/Ubuntu you can install it with the following command:"
    echo "sudo apt-get install libotr5 libotr5-dev"
    exit
fi

echo "Found local version of libotr: ${otr_version}"

if [ "${otr_version}" == '4' ]
then
    make module
fi

if [ "${otr_version}" == '3' ]
then
    echo "module 'otr4' requires native libotr 4.0.0 on the system."
fi

