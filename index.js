/*
 *  Off-the-Record Messaging bindings for nodejs
 *  Copyright (C) 2013  Mokhtar Naamani,
 *                      <mokhtar.naamani@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

//load node C++ native module
var otr = require("./build/Release/otrnat");

if (otr.version() != "4.1.0") {
	console.error("Warning. You are not using the latest version of libotr on your system.");
}

var util = require('util');
var events = require('events');
var BigInt = require('./bigint.js');

exports.version = otr.version;
exports.User = User;
exports.ConnContext = otr.ConnContext;
exports.Session = Session;
exports.POLICY = OTRL_POLICY;
exports.MSGEVENT = OTRL_MSGEVENT;

var debug = function () {};
exports.debugOn = function () {
	debug = function () {
		console.log([].join.call(arguments, " "));
	};
};
exports.debugOff = function () {
	debug = function () {};
};

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

function User(config) {
	if (config && config.keys && config.fingerprints && config.instags) {
		this.state = new otr.UserState();
		this.keys = config.keys;
		this.instags = config.instags;
		this.fingerprints = config.fingerprints;
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
		return null;
	}
}

User.prototype.generateKey = function (accountname, protocol, callback) {
	var user = this;
	this.state.generateKey(this.keys, accountname, protocol, function (err) {
		callback.apply(user, [err, err ? undefined : user.findKey(accountname, protocol)]);
	});
};

User.prototype.accounts = function () {
	return this.state.accounts();
};
User.prototype.fingerprint = function (accountname, protocol) {
	return this.state.fingerprint(accountname, protocol);
};
User.prototype.generateInstag = function (accountname, protocol, callback) {
	try {
		this.state.generateInstag(this.instags, accountname, protocol);
		if (callback) callback(null, this.state.findInstag(accountname, protocol));
	} catch (e) {
		if (callback) callback(e, null);
	}
};
User.prototype.findInstag = function (accountname, protocol) {
	return this.state.findInstag(accountname, protocol);
};

User.prototype.writeFingerprints = function () {
	this.state.writeFingerprintsSync(this.fingerprints);
};
User.prototype.writeTrustedFingerprints = function () {
	this.state.writeTrustedFingerprintsSync(this.fingerprints);
};

User.prototype.findKey = function (accountname, protocol) {
	return this.state.findKey(accountname, protocol);
};
User.prototype.deleteKey = function (accountname, protocol) {
	this.state.deleteKeyOnFile(this.keys, accountname, protocol);
};
User.prototype.writeKeys = function () {
	this.state.writeKeysSync(this.keys);
};

User.prototype.ConnContext = function (accountname, protocol, recipient) {
	return new otr.ConnContext(this.state, accountname, protocol, recipient);
};

User.prototype.exportKeyBigInt = function (accountname, protocol) {
	var k = this.findKey(accountname, protocol);
	if (k) {
		return k.export("BIGINT");
	}
};
User.prototype.exportKeyHex = function (accountname, protocol) {
	var k = this.findKey(accountname, protocol);
	if (k) {
		return k.export("HEX");
	}
};

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
		this.state.importKey(accountname, protocol, key.p, key.q, key.g, key.y, key.x);
	}

	if (!doImport) throw new Error("DSA Key import failed. Unsupported Format.");

	this.state.writeKeysSync(this.keys);
};

User.prototype.getMessagePollDefaultInterval = function () {
	return this.state.getMessagePollDefaultInterval();
};
User.prototype.messagePoll = function (ops, opdata) {
	this.state.messagePoll(ops, opdata);
};

util.inherits(Session, events.EventEmitter);

function Session(user, context, parameters) {
	var _session = this;
	events.EventEmitter.call(this);

	this.user = user;
	this.context = context;
	this.parameters = parameters;
	this.ops = new otr.MessageAppOps(OtrEventHandler(this));
	this.message_poll_interval = setInterval(function () {
		_session.user.messagePoll(_session.ops, 0);
	}, user.getMessagePollDefaultInterval() * 1000 || 70 * 1000);
}

Session.prototype.connect = function () {
	return this.send("?OTR?");
};
Session.prototype.send = function (message, instag) {
	instag = instag || 1; //default instag = BEST
	//message can be any object that can be serialsed to a string using it's .toString() method.
	var msgout = this.ops.messageSending(this.user.state, this.context.accountname(), this.context.protocol(), this
		.context.username(), message.toString(), instag, this.context);
	if (msgout) {
		//frag policy something other than SEND_ALL.. results in a fragment to be sent manually
		this.emit("inject_message", msgout);
	}
};
Session.prototype.recv = function (message) {
	//message can be any object that can be serialsed to a string using it's .toString() method.
	var msg = this.ops.messageReceiving(this.user.state, this.context.accountname(), this.context.protocol(), this.context
		.username(), message.toString(), this.context);
	if (msg) this.emit("message", msg, this.isEncrypted());
};
Session.prototype.close = function () {
	if (this.message_poll_interval) clearInterval(this.message_poll_interval);
	this.ops.disconnect(this.user.state, this.context.accountname(), this.context.protocol(), this.context.username(),
		this.context.their_instance());
	this.emit("shutdown");
};
Session.prototype.start_smp = function (secret) {
	var sec = secret;
	sec = sec || (this.parameters ? this.parameters.secret : undefined);
	if (sec) {
		this.ops.initSMP(this.user.state, this.context, sec);
	} else {
		throw (new Error("No Secret Provided"));
	}
};

Session.prototype.start_smp_question = function (question, secret) {
	if (!question) {
		throw (new Error("No Question Provided"));
	}
	var sec = secret;
	if (!sec) {
		sec = this.parameters ? this.parameters.secrets : undefined;
		if (!sec) throw (new Error("No Secrets Provided"));
		sec = sec[question];
	}

	if (!sec) throw (new Error("No Secret Matched for Question"));

	this.ops.initSMP(this.user.state, this.context, sec, question);
};

Session.prototype.respond_smp = function (secret) {
	var sec = secret ? secret : undefined;
	if (!sec) {
		sec = this.parameters ? this.parameters.secret : undefined;
	}
	if (!sec) throw (new Error("No Secret Provided"));
	this.ops.respondSMP(this.user.state, this.context, sec);
};
Session.prototype.abort_smp = function () {
	this.ops.abortSMP(this.user.state, this.context);
};

Session.prototype.isEncrypted = function () {
	return (this.context.msgstate() === 1);
};
Session.prototype.isAuthenticated = function () {
	return (this.context.trust() === "smp");
};
Session.prototype.extraSymKey = function (use, usedata) {
	var ab = (typeof usedata === 'string') ? str2ab(usedata) : usedata;
	usedata = new Buffer(new Uint8Array(ab));
	var buf = this.ops.extraSymKey(this.user.state, this.context, use, usedata); //returns a Buffer
	return new Uint8Array(buf).buffer;
};

function OtrEventHandler(otrSession) {
	function emit() {
		otrSession.emit.apply(otrSession, arguments);
	}
	return (function (o) {
		debug(otrSession.user.name + ":" + o.EVENT);
		switch (o.EVENT) {
		case "smp_error":
			otrSession.abort_smp();
			emit("smp_failed");
			return;
		case "smp_request":
			emit(o.EVENT, o.question);
			return;
		case "smp_complete":
			emit(o.EVENT);
			return;
		case "smp_failed":
			emit(o.EVENT);
			return;
		case "smp_aborted":
			emit(o.EVENT);
			return;
		case "is_logged_in":
			return 1;
		case "gone_secure":
			emit(o.EVENT);
			return;
		case "gone_insecure":
			emit(o.EVENT);
			return; //never get's called by libotr4.0.0?
		case "policy":
			if (!otrSession.parameters) return OTRL_POLICY("DEFAULT");
			if (typeof otrSession.parameters.policy == 'number') return otrSession.parameters.policy; //todo: validate policy
			return OTRL_POLICY("DEFAULT");
		case "update_context_list":
			emit(o.EVENT);
			return;
		case "max_message_size":
			if (!otrSession.parameters) return 0;
			return otrSession.parameters.MTU || 0;
		case "inject_message":
			emit(o.EVENT, o.message);
			return;
		case "create_privkey":
			emit(o.EVENT, o.accountname, o.protocol);
			return;
		case "new_fingerprint":
			emit(o.EVENT, o.fingerprint);
			return;
		case "write_fingerprints":
			emit(o.EVENT);
			return;
		case "still_secure":
			emit(o.EVENT);
			return;
		case "msg_event":
			debug(o.EVENT + "[ " + OTRL_MSGEVENT(o.event) + " ] - " + o.message);
			if (OTRL_MSGEVENT(o.event) == "RCVDMSG_UNENCRYPTED") {
				emit("message", o.message, false);
			}
			emit(o.EVENT, o.event, o.message, o.err);
			return;
		case "create_instag":
			emit(o.EVENT, o.accountname, o.protocol);
			return;
		case "received_symkey":
			emit(o.EVENT, o.use, (new Uint8Array(o.usedata)).buffer, (new Uint8Array(o.key)).buffer);
			return;
		case "remote_disconnected":
			emit(o.EVENT);
			return;
		default:
			console.error("== UNHANDLED EVENT == :", o.EVENT);
			return;
		}
	});
}

/* --- libotr-4.0.0/src/proto.h   */
var _policy = {
	'NEVER': 0x00,
	'ALLOW_V1': 0x01,
	'ALLOW_V2': 0x02,
	'ALLOW_V3': 0x04,
	'REQUIRE_ENCRYPTION': 0x08,
	'SEND_WHITESPACE_TAG': 0x10,
	'WHITESPACE_START_AKE': 0x20,
	'ERROR_START_AKE': 0x40
};

_policy['VERSION_MASK'] = _policy['ALLOW_V1'] | _policy['ALLOW_V2'] | _policy['ALLOW_V3'];
_policy['OPPORTUNISTIC'] = _policy['ALLOW_V1'] | _policy['ALLOW_V2'] | _policy['ALLOW_V3'] | _policy[
	'SEND_WHITESPACE_TAG'] | _policy['WHITESPACE_START_AKE'] | _policy['ERROR_START_AKE'];
_policy['MANUAL'] = _policy['ALLOW_V1'] | _policy['ALLOW_V2'] | _policy['ALLOW_V3'];
_policy['ALWAYS'] = _policy['ALLOW_V1'] | _policy['ALLOW_V2'] | _policy['ALLOW_V3'] | _policy['REQUIRE_ENCRYPTION'] |
	_policy['WHITESPACE_START_AKE'] | _policy['ERROR_START_AKE'];
_policy['DEFAULT'] = _policy['OPPORTUNISTIC']

function OTRL_POLICY(p) {
	return _policy[p];
}

var _otrl_msgevent = [
	"NONE",
	"ENCRYPTION_REQUIRED",
	"ENCRYPTION_ERROR",
	"CONNECTION_ENDED",
	"SETUP_ERROR",
	"MSG_REFLECTED",
	"MSG_RESENT",
	"RCVDMSG_NOT_IN_PRIVATE",
	"RCVDMSG_UNREADABLE",
	"RCVDMSG_MALFORMED",
	"LOG_HEARTBEAT_RCVD",
	"LOG_HEARTBEAT_SENT",
	"RCVDMSG_GENERAL_ERR",
	"RCVDMSG_UNENCRYPTED",
	"RCVDMSG_UNRECOGNIZED",
	"RCVDMSG_FOR_OTHER_INSTANCE"
];

function OTRL_MSGEVENT(e) {
	return _otrl_msgevent[e];
}


function str2ab(str) {
	var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
	var bufView = new Uint16Array(buf);
	for (var i = 0, strLen = str.length; i < strLen; i++) {
		bufView[i] = str.charCodeAt(i);
	}
	return buf;
}
