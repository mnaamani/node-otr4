var otr = require("../index.js");
var fs = require("fs");

var print = console.error;

print("libotr version:", otr.version());

var user = new otr.User({
	keys: './alice.keys',
	fingerprints: __dirname,
	instags: __dirname
});

var account = user.account("alice@telechat.org", "telechat");

print("generating key...");

account.generateKey(function (err, key) {
	if (err) {
		print("error generating key:", err);
	} else {

		//export an individual key to a json file
		fs.writeFileSync("./alice-key.json", JSON.stringify(key));

		print("generated key fingerprint:", account.fingerprint());
	}
});
