## OTR4 - Off-the-Record Messaging [native-bindings]

This module exposes a simple evented API which wraps the native libotr installed.
Supports only versions **v4.0.0** and above of the library.

Tested on Debian/Ubuntu and Mac OS X

### Install pre-requisits

    npm install -g node-gyp
    
### Additional pre-requisits for debian,ubuntu:

    apt-get install make awk g++ nodejs-dev libotr5 libotr5-dev

### For Mac OS (you need brew and XCode)

    brew install libotr

### Install from npm registry:

    npm install otr4

If the install fails because compiling failed, check that you have all the pre-requisists installed.
After resolving the problem you must reinstall the module:

    npm install otr4 --force

[API Documentation](https://github.com/mnaamani/node-otr4/blob/master/doc/API.md)

### License
GPLv2

### Links
The Excellent OTR Messaging software:
http://www.cypherpunks.ca/otr/

Great guide for writing C++ node.js extensions:
http://kkaefer.github.com/node-cpp-modules/

Very useful set of tools when working with v8/Node:
http://code.google.com/p/v8-juice/wiki/V8Convert
