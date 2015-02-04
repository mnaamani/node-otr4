var libotr = require("../build/Release/otrnat");
var otr = require("../index.js");

var util = require('util');
var events = require('events');
var str2ab = require("./str2ab.js");

module.exports.Session = Session;

util.inherits(Session, events.EventEmitter);

function Session(user, context, parameters) {
	var _session = this;
	events.EventEmitter.call(this);

	this.user = user;
	this.context = context;
	this.parameters = parameters;
	this.ops = new libotr.MessageAppOps(OtrEventHandler(this));
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
			if (!otrSession.parameters) return otr.POLICY.DEFAULT;
			if (typeof otrSession.parameters.policy == 'number') return otrSession.parameters.policy; //todo: validate policy
			return otr.POLICY.DEFAULT;
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
