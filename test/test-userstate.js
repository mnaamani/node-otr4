var otr = require("../index.js");

debug = function(){console.log([].join.call(arguments," "));};

var keys_dir = ".";

var alice_settings ={
    keys:keys_dir+'/alice.keys',
    fingerprints:keys_dir+'/alice.fp',
    instags:keys_dir+'/alice.instags',
    accountname:"alice@telechat.org",
    protocol:"telechat"
};


var alice = new otr.User(alice_settings);
alice.name = "Alice";

make_key_for_user(alice,alice_settings.accountname,alice_settings.protocol);
make_instag_for_user(alice,alice_settings.accountname,alice_settings.protocol);

function make_key_for_user(user,accountname,protocol){
//    if( user.findKey(accountname,protocol) ) return;

    console.log("creating a new key for:",user.name,accountname,protocol);
    user.generateKey(accountname,protocol,function(err,key){
        if(err){
            console.log(err);
            process.exit();
        }else debug("Key Generated Successfully");
    });
}
function make_instag_for_user(user,accountname,protocol){
//    if( user.findInstag(accountname,protocol) return;
    user.generateInstag(accountname,protocol,function(err,instag){
        debug("new instance tag for",user.name,":",instag);
    });
}
