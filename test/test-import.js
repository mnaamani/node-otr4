var name = "alice@telechat.org";
var proto = "telechat";

var otr4 = require("../index.js");

var a = new otr4.User({keys: "otr.private_key", fingerprints:"/tmp/tmp.fp", instags:"/tmp/tmp.tag"});
var b = new otr4.User({keys: "otr.private_key.tmp", fingerprints:"/tmp/tmp.fp", instags:"/tmp/tmp.tag"});

b.importKey(name,proto,a.findKey(name,proto).export());

console.log("imported key finger print matches exported key?",
    a.fingerprint(name,proto) === b.fingerprint(name,proto));

