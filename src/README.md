# Bitcoin Attestation Protocol - BAP
> A simple protocol to create a chain of trust for any kind of information on the Bitcoin blockchain

Javascript classes for working with identities and attestations.

**NOTE: This is work in progress and more documentation will follow.**

# BAP

The BAP class is a wrapper around all BAP functions, including managing IDs and attestations.

```shell
npm install bitcoin-bap --save
```

Example creating a new ID:
```javascript
const HDPrivateKey = 'xprv...';
const bap = new BAP(HDPrivateKey);

// Create a new identity
const newId = bap.newId();
// set the name of the ID
newId.name = 'Social media identity';
// set a description for this ID
newId.description = 'Pseudonymous identity to use on social media sites';
// set identity attributes
newId.addAttribute('name', 'John Doe');
newId.addAttribute('email', 'john@doe.com');

// export the identities for storage
const encryptedExport = bap.exportIds();
```

Signing:
```javascript
const HDPrivateKey = 'xprv...';
const bap = new BAP(HDPrivateKey);
const identity = bap.getId("<identityKey>");

// B protocol data
const opReturn = [
  Buffer.from('19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut').toString('hex'),
  Buffer.from('Hello World!').toString('hex'),
  Buffer.from('text/plain').toString('hex'),
  Buffer.from('utf8').toString('hex'),
];
// signOpReturnWithAIP expects and returns hex values
const signedOpReturn = identity.signOpReturnWithAIP(opReturn);
```

Encryption, every identity has a separate encryption/decryption key:
```javascript
const HDPrivateKey = 'xprv...';
const bap = new BAP(HDPrivateKey);
const identity = bap.getId("<identityKey>");

const publicKey = identity.getEncryptionPublicKey();

const cipherText = identity.encrypt('Hello World!');

const text = identity.decrypt(cipherText);
```

The encryption uses `ECIES` from the `bsv` library:
```javascript
import ECIES from 'bsv/ecies';

const ecies = new ECIES()
ecies.publicKey(publicKey);
return ecies.encrypt(stringData).toString('base64');
```

Other examples:
```javascript
// List the identity keys of all id's 
const idKeys = bap.listIds();

// get a certain id
const id = bap.getId(idKeys[0]);
```
