var otr = require("../index.js");
var fs = require("fs");

var print = console.error;

var user1 = new otr.User({
	keys: '~/alice.keys',
	fingerprints: __dirname,
	instags: __dirname
});

var account = user1.account("alice", "xmpp");

user1.accounts().forEach(function (account) {
	console.log("account:", account.name());
});

print("key fingerprint:", account.fingerprint());

var user2 = new otr.User({
	keys: '~/alice.keys',
	fingerprints: __dirname,
	instags: __dirname
});

var json_key = JSON.parse(fs.readFileSync("./alice-xmpp-key.json"));

account = user2.account("alice", "xmpp");

account.importKey(json_key);

print("key fingerprint:", account.fingerprint());
