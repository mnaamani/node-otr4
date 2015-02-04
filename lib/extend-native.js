var BigInt = require('./bigint.js');

module.exports.extend = function (otr) {

	otr.PrivateKey.prototype.export = function (format) {
		var dsakey = {};
		var key = this;

		['p', 'q', 'g', 'y', 'x'].forEach(function (token) {
			dsakey[token] = key[token];
		});

		if (format == "BIGINT") {
			['p', 'q', 'g', 'y', 'x'].forEach(function (token) {
				dsakey[token] = BigInt.str2bigInt(dsakey[token], 16);
			});
		}

		dsakey.type = '\u0000\u0000';

		return dsakey;
	};

	otr.PrivateKey.prototype.exportPublic = function (format) {
		var key = this.export(format);
		if (key) {
			delete key.x;
			return key;
		}
	};

	otr.PrivateKey.prototype.accountname = function () {
		return this.accountname_;
	};

	otr.PrivateKey.prototype.protocol = function () {
		return this.protocol_;
	};

	otr.PrivateKey.prototype.toString = function () {
		return this.exportPublic("HEX");
	};

	otr.ConnContext.prototype.protocol = function () {
		return this.protocol_;
	};
	otr.ConnContext.prototype.username = function () {
		return this.username_;
	};
	otr.ConnContext.prototype.accountname = function () {
		return this.accountname_;
	};
	otr.ConnContext.prototype.msgstate = function () {
		return this.msgstate_;
	};
	otr.ConnContext.prototype.fingerprint = function () {
		return this.fingerprint_;
	};
	otr.ConnContext.prototype.protocol_version = function () {
		return this.protocol_version_;
	};
	otr.ConnContext.prototype.smstate = function () {
		return this.smstate_;
	};
	otr.ConnContext.prototype.trust = function () {
		return this.trust_;
	};
	otr.ConnContext.prototype.their_instance = function () {
		return this.their_instance_;
	};
	otr.ConnContext.prototype.our_instance = function () {
		return this.our_instance_;
	};
	otr.ConnContext.prototype.master = function () {
		return this.master_;
	};

}
