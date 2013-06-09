/*
 *  Off-the-Record Messaging bindings for nodejs
 *  Copyright (C) 2013  Mokhtar Naamani,
 *                      <mokhtar.naamani@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

//load node C++ native module
var otr=require("./build/Release/otrnat");

if(otr.version()!="4.0.0"){
	console.error("Warning. You are not using the latest version of libotr on your system.");
}

var util = require('util');
var events = require('events');

exports.version = otr.version;
exports.UserState = otr.UserState;

exports.User = User;

function User( config ){
  if(config && config.keys && config.fingerprints && config.instags){
    this.state = new otr.UserState();
    this.keys = config.keys;
    this.instags = config.instags;
    this.fingerprints = config.fingerprints;
    try{    
        this.state.readKeysSync(this.keys);
    }catch(e){ console.error("Warning Reading Keys:",e);}
    try{
        this.state.readFingerprintsSync(this.fingerprints);
    }catch(e){ console.error("Warning Reading Fingerprints:",e);}
    try{
        this.state.readInstagsSync(this.instags);
    }catch(e){ console.error("Warning Reading Instant Tags:",e);}
  }else{
    return null;
  }
}

User.prototype.generateKey = function(accountname,protocol,callback){
    var user = this;
    this.state.generateKey(this.keys,accountname,protocol,function(){
        callback.apply(user,arguments);
    });
};

User.prototype.accounts = function (){
    return this.state.accounts();
};
User.prototype.fingerprint = function(accountname,protocol){
    return this.state.fingerprint(accountname,protocol);
};
User.prototype.generateInstag = function(accountname,protocol,callback){
    try{
        this.state.generateInstag(this.instags,accountname,protocol);
        if(callback) callback(null, this.state.findInstag(accountname,protocol));
    }catch(e){
        if(callback) callback(e,null);
    }
};
User.prototype.findInstag = function(accountname,protocol){
    return this.state.findInstag(accountname,protocol);
};

User.prototype.writeFingerprints = function(){
    this.state.writeFingerprintsSync(this.fingerprints);
};
User.prototype.writeTrustedFingerprints = function(){
    this.state.writeTrustedFingerprintsSync(this.fingerprints);
};

User.prototype.findKey = function(accountname,protocol){
    return this.state.findKey(accountname,protocol);
};
User.prototype.deleteKey = function(accountname,protocol){
    this.state.deleteKeyOnFile(this.keys,accountname,protocol);
};
User.prototype.writeKeys = function(){
    this.state.writeKeysSync(this.keys);
};

User.prototype.ConnContext = function(accountname, protocol, recipient){    
    return new otr.ConnContext(this.state,accountname,protocol,recipient);
};

/*
User.prototype.exportKeyBigInt = function(accountname,protocol){
    var k = this.findKey(accountname,protocol);
    if(k){
        return k.export("BIGINT");
    }
};
User.prototype.exportKeyHex = function(accountname,protocol){
    var k = this.findKey(accountname,protocol);
    if(k){
        return k.export("HEX");
    }
};
User.prototype.importKey = function(accountname,protocol,dsa,base){
    this.state.importKey(accountname,protocol,dsa,base);
    this.state.writeKeysSync(this.keys);
};
*/

User.prototype.getMessagePollDefaultInterval = function(){
    return this.state.getMessagePollDefaultInterval();
};
User.prototype.messagePoll = function(ops,opdata){
    this.state.messagePoll(ops,opdata);
};
