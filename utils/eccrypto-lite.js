var crypto = require("crypto");
var promise =
	typeof Promise === "undefined" ? require("es6-promise").Promise : Promise;
var secp256k1 = require("secp256k1");
var ecdh = require("./ecdh");

module.exports = {
	decryptWithPrivateKey: function(privateKey, encryptedData) {
		const result = decryptWithPrivateKey(privateKey, encryptedData);
		return result;
	},
	encryptWithPublicKey: function(receiverPublicKey, payload) {
		const result = encryptWithPublicKey(receiverPublicKey, payload);
		return result;
	}
};

var encryptWithPublicKey = async function(publicKey, message) {

	//used in encryptedButterParams function
	const encryptedBuffer = function(publicKeyTo, msg, opts) {
		opts = opts || {};
		// Tmp variable to save context from flat promises;
		var ephemPublicKey;
		return new promise(function(resolve) {
			var ephemPrivateKey = opts.ephemPrivateKey || crypto.randomBytes(32);
			ephemPublicKey = getPublic(ephemPrivateKey);
			resolve(derive(ephemPrivateKey, publicKeyTo));
		}).then(function(Px) {
			var hash = sha512(Px);
			var iv = opts.iv || crypto.randomBytes(16);
			var encryptionKey = hash.slice(0, 32);
			var macKey = hash.slice(32);
			var ciphertext = aes256CbcEncrypt(iv, encryptionKey, msg);
			var dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
			var mac = hmacSha256(macKey, dataToMac);
			return {
				iv: iv,
				ephemPublicKey: ephemPublicKey,
				ciphertext: ciphertext,
				mac: mac
			};
		});
	};

	// re-add the compression-flag
	const pubString = "04" + publicKey;

	const encryptedBufferParams = await encryptedBuffer(
		new Buffer(pubString, "hex"),
		Buffer(message)
	);
	//
	const encrypted = {
		iv: encryptedBufferParams.iv.toString("hex"),
		ephemPublicKey: encryptedBufferParams.ephemPublicKey.toString("hex"),
		ciphertext: encryptedBufferParams.ciphertext.toString("hex"),
		mac: encryptedBufferParams.mac.toString("hex")
	};
	return encrypted;
};

var decryptWithPrivateKey = async function(privateKey, encrypted) {
	// remove trailing '0x' from privateKey
	const twoStripped = privateKey.replace(/^.{2}/g, "");

	const encryptedBuffer = {
		iv: new Buffer(encrypted.iv, "hex"),
		ephemPublicKey: new Buffer(encrypted.ephemPublicKey, "hex"),
		ciphertext: new Buffer(encrypted.ciphertext, "hex"),
		mac: new Buffer(encrypted.mac, "hex")
	};

	const decryptedBuffer = await eccdecrypt(
		new Buffer(twoStripped, "hex"),
		encryptedBuffer
	);
	return decryptedBuffer.toString();
};

function sha512(msg) {
	return crypto
		.createHash("sha512")
		.update(msg)
		.digest();
}

function hmacSha256(key, msg) {
	return crypto
		.createHmac("sha256", key)
		.update(msg)
		.digest();
}

var derive = function(privateKeyA, publicKeyB) {
	return new promise(function(resolve) {
		resolve(ecdh.derive(privateKeyA, publicKeyB));
	});
};

function assert(condition, message) {
	if (!condition) {
		throw new Error(message || "Assertion failed");
	}
}

var getPublic = (exports.getPublic = function(privateKey) {
	assert(privateKey.length === 32, "Bad private key");
	// See https://github.com/wanderer/secp256k1-node/issues/46
	var compressed = secp256k1.publicKeyCreate(privateKey);
	return secp256k1.publicKeyConvert(compressed, false);
});

function aes256CbcDecrypt(iv, key, ciphertext) {
	var cipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
	var firstChunk = cipher.update(ciphertext);
	var secondChunk = cipher.final();
	return Buffer.concat([firstChunk, secondChunk]);
}

function aes256CbcEncrypt(iv, key, plaintext) {
	var cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
	var firstChunk = cipher.update(plaintext);
	var secondChunk = cipher.final();
	return Buffer.concat([firstChunk, secondChunk]);
}

function equalConstTime(b1, b2) {
	if (b1.length !== b2.length) {
		return false;
	}
	var res = 0;
	for (var i = 0; i < b1.length; i++) {
		res |= b1[i] ^ b2[i]; // jshint ignore:line
	}
	return res === 0;
}

eccdecrypt = function(privateKey, opts) {
	return derive(privateKey, opts.ephemPublicKey).then(function(Px) {
		var hash = sha512(Px);
		var encryptionKey = hash.slice(0, 32);
		var macKey = hash.slice(32);
		var dataToMac = Buffer.concat([
			opts.iv,
			opts.ephemPublicKey,
			opts.ciphertext
		]);
		var realMac = hmacSha256(macKey, dataToMac);
		assert(equalConstTime(opts.mac, realMac), "Bad MAC");
		return aes256CbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
	});
};

// decrypt(e, pk);
