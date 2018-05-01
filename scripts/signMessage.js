#!/usr/bin/env node

'use strict';

const crypto = require('crypto');
const scrypt = require('scrypt');
const bitcore = require('bitcore-lib');
const Message = require('bitcore-message');
const ttyread = require('ttyread');
const  _  = require('lodash');
const fs = require('fs');
const readline = require('readline');
const program = require('commander');

program
  .description('Sign a message with all private keys')
  .usage('[options] <jsonl-file> <message-file> <output-file>')
  .option('-s, --skip [n]', 'Skip first n private keys')
  .option('-n, --network [network]', 'livenet/testnet/regtest')
  .parse(process.argv);

if (program.args.length !== 3) {
  program.help();
}

if (program.skip) {
  console.log(`Skipping first ${program.skip} keys`);
}

const jsonlFile = program.args[0];
const messageFile = program.args[1];
const message = fs.readFileSync(messageFile, 'utf8');
const outFile = program.args[2];
let network = program.network || 'livenet';
const { Networks } = bitcore;
if (network === 'regtest') {
  Networks.enableRegtest();
  network = 'testnet';
}
const derivationMethods = { SHA512: 0 };

const outStream = fs.createWriteStream(outFile);
let masterKey;
let passphrase;
let secret;
let count = 0;

var lineReader = readline.createInterface({
  input: fs.createReadStream(jsonlFile)
});
lineReader.pause();

ttyread('Enter passphrase: ', { silent: true }, (err, pass) => {
  if (err) {
    throw err;
  }
  passphrase = pass;
  lineReader.resume();
});

lineReader.on('line', (line) => {
  lineReader.pause();
  try {
    line = JSON.parse(line);
  } catch (e) {
    return lineReader.resume();
  }

  if (!line) {
    return lineReader.resume();
  }
  if (line.derivationMethod) {
    masterKey = line;
    return unlockMasterKey((err, unlockedSecret) => {
      if (err) {
        throw err;
      }
      secret = unlockedSecret;
      lineReader.resume();
    });
  }
  count++;
  if (program.skip && count < program.skip) {
    return lineReader.resume();
  }
  if (count % 1000 === 0) {
    console.log(`${new Date().toISOString()} : ${count}`);
  }
  const privKey = decrypt({
    key: secret,
    iv: bitcore.crypto.Hash.sha256sha256(Buffer.from(line.pubKey, 'hex')),
    cipherText: line.cipherText
  });
  let recordPubkey;
  try {
    recordPubkey = new bitcore.PublicKey(line.pubKey);
  } catch (e) {
    console.log('ERROR: invalid public key in json export: ' + line.pubKey);
    throw e;
  }

  var privateKey = bitcore.PrivateKey.fromObject({
    bn: privKey,
    compressed: recordPubkey.compressed,
    network: Networks[network]
  });

  var pubKey = privateKey.toPublicKey();

  if (recordPubkey.toString('hex') !== pubKey.toString('hex')) {
    console.error('ERROR: ' + 'public key: ' + line.pubKey + ' in json export did not match: ' + pubKey);
    throw new Error('keys did not match as expected');
  }

  var signature = Message(message).sign(privateKey);

  var obj = {
    address: pubKey.toAddress(network).toString(),
    signature: signature
  };

  outStream.write(JSON.stringify(obj) + '\n');
  lineReader.resume();
});

lineReader.on('close', () => {
  console.log('Done!');
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
  decryptSecret({
    cipherText: masterKey.cipherText,
    salt: masterKey.salt,
    derivationOptions: {
      method: derivationMethods[masterKey.derivationMethod],
      rounds: masterKey.rounds
    },
    passphrase
  }, (err, secret) => {
    if (err) {
      console.error('Could not decrypt.');
      return callback(err);
    }
    callback(null, secret);
  });
}

function sha512KDF(passphrase, salt, derivationOptions, callback) {
  if (!derivationOptions || derivationOptions.method !== 0 || !derivationOptions.rounds) {
    return callback(new Error('SHA512 KDF method was called for, ' +
      'yet the derivations options for it were not supplied.'));
  }
  var rounds =  derivationOptions.rounds || 1;
  // if salt was sent in as a string, we will have to assume the default encoding type
  if (!Buffer.isBuffer(salt)) {
    salt = new Buffer(salt, 'hex');
  }
  var derivation = Buffer.concat([new Buffer(''), new Buffer(passphrase), salt]);
  for (var i = 0; i < rounds; i++) {
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
  return opts && opts.method === 0 ? sha512KDF : scryptKDF;
};

function decryptSecret(opts, callback) {
  var hashFunc = hashPassphrase(opts.derivationOptions);
  hashFunc(opts.passphrase, opts.salt, opts.derivationOptions, function(err, hashedPassphrase) {
    if (err) {
      return callback(err);
    }
    opts.key = hashedPassphrase;
    callback(null, decrypt(opts));
  });
};

function decrypt(opts) {
  if (!Buffer.isBuffer(opts.key)) {
    opts.key = Buffer.from(opts.key, 'hex');
  }
  var secondHalf;
  if (opts.iv) {
    secondHalf = opts.iv.slice(0, 16);
  } else {
    secondHalf = opts.key.slice(32, 48); // AES256-cbc IV
  }
  var cipherText = Buffer.from(opts.cipherText, 'hex');
  var firstHalf = opts.key.slice(0, 32); // AES256-cbc shared key
  var AESDecipher = crypto.createDecipheriv('aes-256-cbc', firstHalf, secondHalf);
  var plainText;
  try {
    plainText = Buffer.concat([AESDecipher.update(cipherText), AESDecipher.final()]).toString('hex');
  } catch (e) {
    throw e;
  }

  return plainText;
};
