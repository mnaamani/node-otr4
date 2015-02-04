var Session = require("./Session.js").Session;

module.exports.Contact = Contact;

/** Contact
 * @constructor
 * @alias module:otr.Contact
 * @argument {User} user - instance of {@link module:otr.User User}
 * @argument {Account} account - instance of {@link module:otr.Account Account}
 * @argument {string} name - name of the contact
 */
function Contact(user, account, name) {
	if (!(user instanceof User)) {
		throw new TypeError("first argument must be an instance of User");
	}
	if (!(account instanceof Account)) {
		throw new TypeError("second argument must be an instance of Account");
	}
	if (typeof name !== 'string') {
		throw new TypeError("third argument must be a string");
	}

	/** Getter for name of contact
	 * @method
	 * @returns {string} contact name
	 */
	this.name = function () {
		return name;
	};

	/** Returns an array of knwon Fingerprint instances for this contact.
	 * @method
	 * @returns {array} Array of Fingerprint instances.
	 */
	this.fingerprints = function () {
		var context = new otr.ConnContext(user.state, account.name(), account.protocol(), name);
		return context.masterFingerprints();
	};

	/** Setup an OTR session with the contact.
	 * @method
	 * @argument {Object} [parameters]
	 * @returns {Session}
	 */
	this.openSession = function (parameters) {
		return new Session(user, account, this, parameters);
	};

}
