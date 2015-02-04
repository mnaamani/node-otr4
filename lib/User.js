var BigInt = require('./bigint.js');
var expandHomeDir = require("./homedir.js");
var otrlib = require("../build/Release/otrnat");
var Account = require("./Account.js").Account;

module.exports.User = User;

function User(files) {
	//file paths are required
	if (files && files.keys && files.fingerprints && files.instags) {
		this.state = new otrlib.UserState();
		this.keys = files.keys;
		this.instags = files.instags;
		this.fingerprints = files.fingerprints;
		try {
			this.state.readKeysSync(this.keys);
		} catch (e) {
			console.error("Warning Reading Keys:", e);
		}
		try {
			this.state.readFingerprintsSync(this.fingerprints);
		} catch (e) {
			console.error("Warning Reading Fingerprints:", e);
		}
		try {
			this.state.readInstagsSync(this.instags);
		} catch (e) {
			console.error("Warning Reading Instant Tags:", e);
		}
	} else {
		return undefined;
	}
}

User.prototype.loadKeysFromFS = function (filename) {
	this.state.readKeysSync(expandHomeDir(filename));
};

User.prototype.loadFingerprintsFromFS = function (filename) {
	this.state.readFingerprintsSync(expandHomeDir(filename));
};

User.prototype.loadInstagsFromFS = function (filename) {
	this.state.readInstagsSync(expandHomeDir(filename));
};

User.prototype.saveFingerprintsToFS = function (filename) {
	this.state.writeFingerprintsSync(expandHomeDir(filename));
};

User.prototype.saveKeysToFS = function (filename) {
	this.state.writeKeysSync(expandHomeDir(filename));
};

User.prototype.saveInstagsToFS = function (filename) {
	this.state.writeInstagsSync(expandHomeDir(filename));
};

User.prototype.writeFingerprints = function () {
	this.state.writeFingerprintsSync(this.fingerprints);
};

User.prototype.writeTrustedFingerprints = function () {
	this.state.writeTrustedFingerprintsSync(this.fingerprints);
};

/*:: old API :: replaced
User.prototype.accounts = function () {
	return this.state.accounts();
};
*/

/*:: new API - replaces old User.prototype.accounts() method */
User.prototype.accounts = function () {
	var user = this,
		accounts = this.state.accounts(),
		list = [];
	accounts.forEach(function (account) {
		list.push(new Account(user, account.accountname, account.protocol));
	});
	return list;
};

User.prototype.getMessagePollDefaultInterval = function () {
	return this.state.getMessagePollDefaultInterval();
};

User.prototype.messagePoll = function (ops, opdata) {
	this.state.messagePoll(ops, opdata);
};

User.prototype.account = function (accountname, protocol) {
	return new Account(this, accountname, protocol);
};

//:: old API :: deprecated
User.prototype.generateKey = function (accountname, protocol, callback) {
	var user = this;
	this.state.generateKey(this.keys, accountname, protocol, function (err) {
		callback.apply(user, [err, err ? undefined : user.findKey(accountname, protocol)]);
	});
};

//:: old API :: deprecated
User.prototype.fingerprint = function (accountname, protocol) {
	return this.state.fingerprint(accountname, protocol);
};

//:: old API :: deprecated
User.prototype.generateInstag = function (accountname, protocol, callback) {
	try {
		this.state.generateInstag(this.instags, accountname, protocol);
		if (callback) callback(null, this.state.findInstag(accountname, protocol));
	} catch (e) {
		if (callback) callback(e, null);
	}
};

//:: old API :: deprecated
User.prototype.findInstag = function (accountname, protocol) {
	return this.state.findInstag(accountname, protocol);
};

//:: old API :: deprecated
User.prototype.findKey = function (accountname, protocol) {
	return this.state.findKey(accountname, protocol);
};

//:: old API :: deprecated
User.prototype.deleteKey = function (accountname, protocol) {
	this.state.deleteKeyOnFile(this.keys, accountname, protocol);
};

//:: old API :: deprecated
User.prototype.writeKeys = function () {
	this.state.writeKeysSync(this.keys);
};

//:: old API :: deprecated
User.prototype.ConnContext = function (accountname, protocol, recipient) {
	return new otrlib.ConnContext(this.state, accountname, protocol, recipient);
};

//:: old API :: deprecated
User.prototype.exportKeyBigInt = function (accountname, protocol) {
	var k = this.findKey(accountname, protocol);
	if (k) {
		return k.export("BIGINT");
	}
};

//:: old API :: deprecated
User.prototype.exportKeyHex = function (accountname, protocol) {
	var k = this.findKey(accountname, protocol);
	if (k) {
		return k.export("HEX");
	}
};

//:: old API :: deprecated
User.prototype.importKey = function (accountname, protocol, dsa, base) {

	var key = {
		p: null,
		q: null,
		g: null,
		y: null,
		x: null
	};
	var doImport = true;

	['p', 'q', 'g', 'y', 'x'].forEach(function (t) {
		var bi;
		switch (typeof dsa[t]) {
		case 'string':
			bi = BigInt.str2bigInt(dsa[t], base || 16);
			break;
		case 'object':
			bi = dsa[t];
			break;
		default:
			doImport = false;
			bi = null;
		}
		if (bi !== null) {
			key[t] = BigInt.bigInt2str(bi, 16);
		} else doImport = false;
	});

	if (doImport) {
		this.state.importPrivKey(accountname, protocol, key.p, key.q, key.g, key.y, key.x);
	}

	if (!doImport) throw new Error("DSA Key import failed. Unsupported Format.");

	this.state.writeKeysSync(this.keys);
};
