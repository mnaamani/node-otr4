module:
	node-gyp configure
	node-gyp build

clean:
	node-gyp clean

docs:
	rm -fr doc/html/
	jsdoc -d doc/html index.js lib/User.js lib/Account.js lib/Contact.js lib/Session.js lib/POLICY.js lib/MSGEVENT.js
