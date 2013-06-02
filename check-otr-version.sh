#!/bin/bash

# use the C pre-processor to get the version of libotr on the system

cat >tmp.h <<EOF
 #include <libotr/version.h>
 #ifdef OTRL_VERSION_MAJOR
    otrl-version OTRL_VERSION_MAJOR OTRL_VERSION_MINOR OTRL_VERSION_SUB
 #else
    otrl-version 0 0 0
 #endif
EOF

if [ -e tmp.h ]
then
 #prints the major version or 0 if libotr dev headers not found
 cc -E tmp.h 2>/dev/null | grep "otrl-version" | awk '{print $2}'
 rm tmp.h
fi
