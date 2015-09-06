#### Quick Tutorial on using the otr4 module

	var otr = require("otr4")
	  , version = otr.version(); // "4.1.0"


First thing we need is to load the account data.
An account is a combination of an OTR key, an instance tag, and known buddy fingerprints.
Keys are stored in a keystore file. Instance tags are stored in an instance tags file, and fingerprints are stored in a fingerprints file.

The **otr.User** class is a container for loading/saving and managing these files.

### Loading account data
We must pass specify the paths to the account data files when creating an **otr.User** object:

	var user = new otr.User({
		keys: "~/.purple/otr.private_key",
		fingerprints: "~/.purple/otr.fingerprints",
		instags: "~/otr.instags"
	});

A tilda '~' represents the user's home directory and will be resolved accordingly. If specified files exist the keys, fingerprints and instance tags will be loaded automatically. A warning will be logged to the console otherwise.

Files are loaded and parsed synchronously.

### Accounts

An account is identified by an account name and protocol. Accounts are encapsulated in an **Account** object returned by the **account** method of the otr.User object.

Lets create a new account, with accountname "alice@jabber.org" and protocol "xmpp":

	var account = user.account("alice@jabber.org","xmpp");

generate an OTR key::

	account.generateKey(function(err, privkey){
		if(err){
			console.log("Something went wrong!", err.message);
		}else{
			console.log("Generated key successfully.");
		}
	});

and an instance tag:

	account.generateInstag(function(err,instag){
		if(err){
			console.log("failed to generate instance tag!", err);
		}else{
			console.log("new instance tag:", instag);
		}
	});


The public key fingerprint of the OTR key is retrieved with the fingerprint method:

	account.fingerprint(); // "65D366AF CF9B065F 41708CB0 1DC26F61 D3DF5935"


### Contacts

Now that we have created an account and our OTR key, we can chat with remote parties (a contact).
A contact is identified by a username. Lets say we want to chat with Bob, we create a **Contact** object using the **contact** method of our account:

	var bob = account.contact("Bob");

Once we have a Contact object we can setup an OTR conversation, using the **openSession** method of the contact:

	var session = bob.openSession();


### Sessions

A session is an event emitter. The first thing todo is to hookup the session to the underlying network connection/socket/xmpp transport.
Lets assume we have established a TCP socket **"client"** to our contact:

	var net = require('net');

	var client = net.connect({
			....
	});

when receiving data from the network pass it into the session's recv method

	client.on('data', function(data) {
		session.recv(data);
	});

when a session emits the inject_message with a message fragment send it to the remote end:

	session.on("inject_message",function(fragment){
		client.write(fragment);
	});


To start an OTR conversation, we call the **start** method of the session.

	session.start();


When connecting to a contact for the first time, or if we have not saved their fingerprint to file
two events will be fired by the session, new_fingerprint and write_fingerprints:

	session.on("new_fingerprint",function(fingerprint){
	   console.log("new contact's fingerprint:", fingerprint);
	});

	session.on("write_fingerprints",function(){
	   user.writeFingerprints();
	});

It will be followed by a "gone_secure" event:

	session.on("gone_secure",function(){
		console.log("connection secure.");
		console.log("contact's fingerprint:",session.theirFingerprint());
	});

after which we can begin to exchange messages with contact:

	session.send("hello");

When the contact sends us a message, the session will fire the "message" event:

	session.on("message",function(message, private){
		if(private){
			//OTR is active and message was sent privately (encrypted)
			console.log("[private]",message);
		}else{
			//recevied a message in plaintext
			console.log("[plaintext]",message);
		}
	});


At anytime during a secure session we can perform authentication using the Socialist Millionaire's Protocol, (SMP):

	var session.smpStart("shared-secret");


You may receive an smp event and respond:

	session.on("smp", function(type) {
		switch (type) {
			case "request":
				session.smpRespond("shared-secret");
				break;

			case "complete":
				console.log("SMP successful");
				break;
		}
	});

on successful SMP authentication the "smp" event will be emitted with type argument "complete".
This will also be followed by a "write_fingerprints" event.

### API documentation
See the full [API docs](http://www.mokhtar.net/projects/otr4/docs/) for more detailed documentation.
