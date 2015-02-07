var BigInt = require('./bigint.js');

module.exports.extend = function (libotr) {

	libotr.PrivateKey.prototype.export = function (format) {
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

	libotr.PrivateKey.prototype.exportPublic = function (format) {
		var key = this.export(format);
		if (key) {
			delete key.x;
			return key;
		}
	};

	libotr.PrivateKey.prototype.accountname = function () {
		return this.accountname_;
	};

	libotr.PrivateKey.prototype.protocol = function () {
		return this.protocol_;
	};

	libotr.PrivateKey.prototype.toString = function () {
		return this.exportPublic("HEX");
	};

	libotr.ConnContext.prototype.protocol = function () {
		return this.protocol_;
	};
	libotr.ConnContext.prototype.username = function () {
		return this.username_;
	};
	libotr.ConnContext.prototype.accountname = function () {
		return this.accountname_;
	};
	libotr.ConnContext.prototype.msgstate = function () {
		return this.msgstate_;
	};
	libotr.ConnContext.prototype.fingerprint = function () {
		return this.fingerprint_;
	};
	libotr.ConnContext.prototype.protocol_version = function () {
		return this.protocol_version_;
	};
	libotr.ConnContext.prototype.smstate = function () {
		return this.smstate_;
	};
	libotr.ConnContext.prototype.trust = function () {
		return this.trust_;
	};
	libotr.ConnContext.prototype.their_instance = function () {
		return this.their_instance_;
	};
	libotr.ConnContext.prototype.our_instance = function () {
		return this.our_instance_;
	};
	libotr.ConnContext.prototype.master = function () {
		return this.master_;
	};

	libotr.ConnContext.prototype.toJSON = function () {
		return ({
			'protocol': this.protocol(),
			'username': this.username(),
			'accountname': this.accountname(),
			'msgstate': this.msgstate(),
			'protocol_version': this.protocol_version(),
			'smstate': this.smstate(),
			'fingerprint': this.fingerprint(),
			'trust': this.trust(),
			'their_instance': this.their_instance(),
			'our_instance': this.our_instance()
		});
	};

	libotr.ConnContext.prototype.toString = libotr.ConnContext.prototype.inspect = function () {
		return JSON.stringify(this.toJSON());
	};

	libotr.UserState.prototype.importKey = function (accountname, protocol, dsa, base) {
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
			this.importPrivKey(accountname, protocol, key.p, key.q, key.g, key.y, key.x);
		}

		if (!doImport) throw new Error("DSA Key import failed. Unsupported Format.");
	};

	libotr.Fingerprint.prototype.fingerprint = libotr.Fingerprint.prototype.toString = function () {
		return this.human_;
	};

	libotr.Fingerprint.prototype.inspect = function () {
		return JSON.stringify({
			fingerprint: this.human_,
			trust: this.trust_
		});
	};

	libotr.Fingerprint.prototype.equals = function (str) {
		if (str === "" || !str) return false; //dont compare null strings or undefined
		return this.toString() === str;
	};

	//get or set trust level of fingerprint
	libotr.Fingerprint.prototype.trust = function (trust) {
		//set new trust
		if (typeof trust === 'string') {
			this.trust_ = trust;
		}
		return this.trust_;
	};

	libotr.Fingerprint.prototype.untrust = function () {
		this.trust_ = "";
	};

	libotr.Fingerprint.prototype.delete = function () {
		this.forget();
	};
};
