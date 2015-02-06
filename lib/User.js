var BigInt = require('./bigint.js');
var expandHomeDir = require("./homedir.js");
var libotr = require("../build/Release/otrnat");
var otr = require("../index.js");
var fs = require("fs");
var path = require("path");

module.exports.User = User;

/** Represents a users's keys, fingerprints and instance tags
 *  stored on the file system. Paths are required and should not be directories. If no file paths are provided
 *  the User object will not be created. File paths can start with a "~" tilda which is interpreted to mean the application
 *	user's home directory.
 *  @alias module:otr.User
 *  @constructor
 *  @param {Object} files object with string properties: keys, fingerprints, instags
 */
function User(files) {
	var user = this;

	if (files && files.keys && files.fingerprints && files.instags) {
		user.state = new libotr.UserState();
		user.keys = expandHomeDir(files.keys);
		user.instags = expandHomeDir(files.instags);
		user.fingerprints = expandHomeDir(files.fingerprints);

		try {
			if (fs.statSync(user.keys).isDirectory()) {
				console.error("Warning path to keys is a directory, using default file name.");
				user.keys = path.join(user.keys, "otr.private_key");
			}
			user.loadKeysFromFS(user.keys);
		} catch (e) {
			console.error("Warning Reading Keys:", e.message);
		}

		try {
			if (fs.statSync(user.fingerprints).isDirectory()) {
				console.error("Warning path to fingerprints is a directory, using default file name.");
				user.fingerprints = path.join(user.fingerprints, "otr.fingerprints");
			}
			user.loadFingerprintsFromFS(user.fingerprints);
		} catch (e) {
			console.error("Warning Reading Fingerprints:", e.message);
		}

		try {
			if (fs.statSync(user.instags).isDirectory()) {
				console.error("Warning path to instags is a directory, using default file name.");
				user.instags = path.join(user.instags, "otr.instags");
			}
			user.loadInstagsFromFS(user.instags);
		} catch (e) {
			console.error("Warning Reading Instance Tags:", e.message);
		}

	} else {
		return undefined;
	}
}

/** Reads private keys (Accounts) from file provided. It replaces the previously loaded keys.
 * @method
 * @param {string} filename - source path of private keys file.
 * @throws {Error}
 */
User.prototype.loadKeysFromFS = function (filename) {
	this.state.readKeysSync(expandHomeDir(filename));
};

/** Reads fingerprints (Contacts) from file provided. It replaces the previously loaded fingerprints.
 * @method
 * @param {string} filename - source path of fingerprints file.
 * @throws {Error}
 */
User.prototype.loadFingerprintsFromFS = function (filename) {
	this.state.readFingerprintsSync(expandHomeDir(filename));
};

/** Reads instags from file provided. It replaces previously loaded instags.
 * @method
 * @param {string} filename - source path of instags file.
 * @throws {Error}
 */
User.prototype.loadInstagsFromFS = function (filename) {
	this.state.readInstagsSync(expandHomeDir(filename));
};

/** Writes the fingerprints from memory to the file system. This method can be used optionally to save new fingerprints
	after connecting to a new contact.
	* @method
	* @throws {Error}
	*/
User.prototype.writeFingerprints = function () {
	this.state.writeFingerprintsSync(this.fingerprints);
};

/**
 * Writes only fingerprints which have been authenticated from memory to the file system.
 * @method
 * @throws {Error}
 */
User.prototype.writeTrustedFingerprints = function () {
	this.state.writeTrustedFingerprintsSync(this.fingerprints);
};

/**
 * Returns and array of {@link module:otr.Account Account} instances, representing all the user accounts.
 * If no accounts exist, the return value will be an empty array.
 * @method
 * @returns {Array} Array of {@link module:otr.Account Account} instances.
 */
User.prototype.accounts = function () {
	var user = this,
		accounts = this.state.accounts(),
		list = [];
	accounts.forEach(function (account) {
		list.push(new otr.Account(user, account.accountname, account.protocol));
	});
	return list;
};

/**
 * Select an account or create a new account with given accountname and protocol
 * @method
 * @argument {string}  accountname
 * @argument {string}  protocol
 * @returns  {Account} instance of {@link module:otr.Account Account} class
 */
User.prototype.account = function (accountname, protocol) {
	return new otr.Account(this, accountname, protocol);
};

User.prototype.getMessagePollDefaultInterval = function () {
	return this.state.getMessagePollDefaultInterval();
};

User.prototype.messagePoll = function (ops, opdata) {
	this.state.messagePoll(ops, opdata);
};
