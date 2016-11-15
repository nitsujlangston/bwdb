'use strict';
var crypto = require('crypto');
var bitcore = require('bitcore-lib');
var Message = require('bitcore-message');
var ttyread = require('ttyread');
var async = require('async');
var  _  = require('lodash');
var fs = require('fs');
var program = require('commander');

program
  .description('Sign a message with all private keys')
  .usage('<json-file> <message-file> <output-file>')
  .parse(process.argv);

if(program.args.length !== 3) {
  program.help();
}

var jsonFile = program.args[0];
var messageFile = program.args[1];
var outFile = program.args[2];

var message = fs.readFileSync(messageFile, 'utf8');

var concurrency = 4;
var keyEntries = require(jsonFile);
var livenet = bitcore.Networks.livenet;
var masterKey = getMasterKey(keyEntries);
var derivationMethods = { 'SHA512': 0 };

unlockMasterKey(function(err, secret) {
  var self = this;
  if(err) {
    throw err;
  }

  var total = 0;

  console.log('Counting private keys...');
  for(var i = 0; i < keyEntries.length; i++) {
    var record = keyEntries[i];
    if(record.type === 'encrypted private key') {
      total++;
    }
  }

  console.log('Processing ' + total + ' private keys');

  var count = 0;
  var outStream = fs.createWriteStream(outFile);
  outStream.write('[\n');

  async.eachLimit(keyEntries, concurrency, function(record, next) {
    if (record.type === 'encrypted private key') {
      count++;
      if(count % 1000 === 0) {
        console.log((new Date()).toISOString() + ': ' + count);
      }

      decrypt({
        key: secret,
        iv: bitcore.crypto.Hash.sha256sha256(new Buffer(record.pubKey, 'hex')),
        cipherText: record.cipherText
      }, function(err, privKey) {
        if(err) {
          return callback(err);
        }
        var privateKey = bitcore.PrivateKey.fromObject({
          bn: privKey,
          compressed: true,
          network: livenet
        });

        var signature = Message(message).sign(privateKey);

        var pubKey = privateKey.toPublicKey();

        if (record.pubKey !== pubKey.toString('hex')) {
          return callback(new Error('public key: ' + record.pubKey + ' in json export did not match: ' + pubKey));
        }

        var obj = {
          address: pubKey.toAddress().toString(),
          signature: signature
        };

        outStream.write(JSON.stringify(obj, null, 2));
        if(count < total) {
          outStream.write(',\n');
        } else {
          outStream.write('\n');
        }

        next();
      });
    } else {
      setImmediate(next);
    }
  }, function(err) {
    if(err) {
      throw(err);
    }

    outStream.write(']\n');

    console.log('Done');
  });
});

/*
   Important notes:

   How the encryption/decryption schemes work.
   1. The user's passphrase and salt are hashed using scrypt algorithm. You must store the salt.
   On modern hardware this hashing function should take 1-2 seconds.
   2. The resulting hash is 48 bytes. The first 32 bytes of this hash is the "key" and the last
   16 bytes is the "iv" to decrypt the master key using AES256-cbc.
   3. The plaintext "master key" is always 32 bytes and should be as random as possible.
   You may pass in the plaintext master key to encryptSecret -or- /dev/random will be consulted.
   4. The cipherText of the master key must be stored just like the salt. For added security, you
   might store the cipherText of the master key separate from the cipherText.
   For example, if an attacker discovers your passphrase and salt (the most likely scenario), they would
   still require the cipherText of the master key in order to decrypt the cipherText of your private keys.
   Storing your encrypted master key on another device would be a better choice than keeping your salt,
   the cipherText of your master key and the cipherText of your private keys on the same computer system.
   5. The plaintext master key is then used to encrypt/decrypt the bitcoin private keys. The private keys'
   corresponding public key is used as the IV for the procedure.


   Specific notes regarding how private keys are transferred from a traditional "wallet.dat" file used with
   Bitcoin Core's Wallet:

   1. Bitcoin Core's Wallet uses Berkeley DB version 4.8 to store secp256k1 elliptic curve private keys in WIF format.
   2. The same Berkeley DB, internally called "main", also stores compressed public keys for the above private keys,
   the master keys used to encrypt the above private keys and bitcoin transaction details relevant to those private keys
   3. The underlying data structure for the Berkeley database is the B-Tree (balanced tree). This is a key-value data
   structure, therefore the database is a key-value database.
   Berkeley DB documentation also refers to this as "key-record"
   This means that the data contained in this B-Tree is organized for high speed retrieval based on a key.
   In other words the database is optimized for lookups.
   4. The filename for this database file is called "wallet.dat" historically,
   but you can rename it to whatever suits you

*/
function unlockMasterKey(callback) {
  async.retry(3, function(next) {
    getPassphrase(function(err, passphrase) {
      decryptSecret({
        cipherText: masterKey.cipherText,
        salt: masterKey.salt,
        derivationOptions: {
          method: derivationMethods[masterKey.derivationMethod],
          rounds: masterKey.rounds
        },
        passphrase: passphrase
      }, function(err, secret) {
        if (err) {
          console.log('Could not decrypt.');
          return next(err);
        }
        next(null, secret);
      });
    });
  }, callback);
}

function getPassphrase(callback) {
  ttyread('Enter passphrase: ', {silent: true}, callback);
};

function sha512KDF(passphrase, salt, derivationOptions, callback) {
  if (!derivationOptions || derivationOptions.method !== 0 || !derivationOptions.rounds) {
    return callback(new Error('SHA512 KDF method was called for, ' +
      'yet the derivations options for it were not supplied.'));
  }
  var rounds =  derivationOptions.rounds || 1;
  //if salt was sent in as a string, we will have to assume the default encoding type
  if (!Buffer.isBuffer(salt)) {
    salt = new Buffer(salt, 'hex');
  }
  var derivation = Buffer.concat([new Buffer(''), new Buffer(passphrase), salt]);
  for(var i = 0; i < rounds; i++) {
    derivation = crypto.createHash('sha512').update(derivation).digest();
  }
  callback(null, derivation);
};

function scryptKDF(passphrase, salt, derivationOptions, callback) {
  var opts = _.assign({ N: Math.pow(2, 14), r: 8, p: 8 }, derivationOptions);
  scrypt.hash(passphrase, opts, 48, salt, function(err, res) {
    if (err) {
      return callback(err);
    }
    callback(null, res);
  });
};

function hashPassphrase(opts) {
  return opts && opts.method === 0 ?
    sha512KDF : scryptKDF;
};

function decryptSecret(opts, callback) {
  var hashFunc = hashPassphrase(opts.derivationOptions);
  hashFunc(opts.passphrase, opts.salt, opts.derivationOptions, function(err, hashedPassphrase) {
    if (err) {
      return callback(err);
    }
    opts.key = hashedPassphrase;
    decrypt(opts, callback);
  });
};

function decrypt(opts, callback) {
  if (!Buffer.isBuffer(opts.key)) {
    opts.key = new Buffer(opts.key, 'hex');
  }
  var secondHalf;
  if (opts.iv) {
    secondHalf = opts.iv.slice(0, 16);
  } else {
    secondHalf = opts.key.slice(32, 48); //AES256-cbc IV
  }
  var cipherText = new Buffer(opts.cipherText, 'hex');
  var firstHalf = opts.key.slice(0, 32); //AES256-cbc shared key
  var AESDecipher = crypto.createDecipheriv('aes-256-cbc', firstHalf, secondHalf);
  var plainText;
  try {
    plainText = Buffer.concat([AESDecipher.update(cipherText), AESDecipher.final()]).toString('hex');
  } catch(e) {
    return callback(e);
  }

  setImmediate(function() {
    callback(null, plainText);
  });
};

function getMasterKey(json) {
  for(var i = json.length - 1; i >= 0; i--) {
    if (json[i]['type'] === 'master') {
      return json[i];
    }
  }
}
