var otr = require("../index.js");
var fs = require("fs");

var print = console.error;

var user = new otr.User({
	keys: './bob.keys',
	fingerprints: __dirname,
	instags: __dirname
});

var account = user.account("bob@telechat.org", "telechat");

print("generating key...");

account.generateKey(function (err, key) {
	if (err) {
		print("error generating key:", err);
	} else {

		print("generated key fingerprint:", account.fingerprint());
	}
});
