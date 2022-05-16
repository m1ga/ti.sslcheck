const win = Ti.UI.createWindow({});
const sslcheck = require('ti.sslcheck');
const securityManager = sslcheck.createSecurityManager();
const httpClient = Ti.Network.createHTTPClient({
	onload: function(e) {},
	onerror: function(e) {
		Ti.API.error(e.error);
	},
	timeout: 10000,
	securityManager: securityManager
});

httpClient.addEventListener("sslCheck", e => {
	console.log("fingerprint", e.fingerprint);
	console.log("issuedByCName", e.issuedByCName);
	console.log("issuedByDName", e.issuedByDName);
	console.log("issuedByOName", e.issuedByOName);
	console.log("issuedByUName", e.issuedByUName);
	console.log("issuedToCName", e.issuedToCName);
	console.log("issuedToDName", e.issuedToDName);
	console.log("issuedToOName", e.issuedToOName);
	console.log("issuedToUName", e.issuedToUName);
	console.log("issuedToUName", e.issuedToUName);
	console.log("validNotAfter", e.validNotAfter);
	console.log("validNotBefore", e.validNotBefore);
})

httpClient.open('GET', 'https://tidev.io/');
httpClient.send();
win.open();
