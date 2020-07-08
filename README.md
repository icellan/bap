# Bitcoin Attestation Protocol - BAP
> A simple protocol to create a chain of trust for any kind of information on the Bitcoin blockchain

Authors: Siggi

Special thanks to Attila Aros & Satchmo

Inspired by the [AUTHOR IDENTITY Protocol](https://github.com/BitcoinFiles/AUTHOR_IDENTITY_PROTOCOL)

# Intro

The design goals:

1. A simple protocol for generic attestation of data, without the need to publish the data itself
2. Decouple the signing with an address from the funding source address (ie: does not require any on-chain transactions from the signing identity address)
3. Allow for rotation of signing keys without having to change the existing attestations

# Use cases

- Identity system: A user can create multiple self-managed identities, keeping all PII data secure in a wallet or app. The user can get provable verification of identity attributes from trusted authorities, without leaking PII data or keys.
- Power of attorney: A user can attest to giving a power of attorney to another user with a certain key
- Blacklisting

# Protocol

The protocol is defined using the [Bitcom](https://bitcom.bitdb.network/) convention. The signing is done using the [AUTHOR IDENTITY Protocol](https://github.com/BitcoinFiles/AUTHOR_IDENTITY_PROTOCOL).

- The prefix of the protocol is `1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT`;

```
1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT
[ID|ATTEST|REVOKE]
[ID Key|URN Attestation Hash]
[Sequence|Address]
|
[AIP protocol address]
[AIP Signing Algorithm]
[AIP Signing Address]
[AIP Signature]
```
By default, all fields are signed, so the optional indices of the AIP can be left out.

The `Sequence` is added to the transaction to prevent replay of the transaction in case of a revocation. The transaction from the same signatory, with the highest `Sequence` is the current one.

The fourth field is used for the bitcoin signing address in an `ID` transaction only.

Example:

```
1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT
ATTEST
d4bcdd0f437d0d3bc588bb4e861d2e83e26e8bf9566ae541a5d43329213b1b13
0
|
15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva
BITCOIN_ECDSA
1Po6MLAPJsSAGyE8sXw3CgWcgxumNGjyqm
G8wW0NOCPFgGSoCtB2DZ+0CrLrh9ywAl0C5hnx78Q+7QNyPYzsFtkt4/TXkzkTwqbOT3Ofb1CYdNUv5a/jviPVA=
```

## URN - Uniform Resource Names
The protocol makes use of URN's as a data carrier for the attestation data, as defined by the [w3c](https://www.w3.org/TR/uri-clarification/).

URN's look like:

```
urn:[namespace identifier]:[...URN]
```

Examples for use in BAP:

Identity:
```
urn:bap:id:[Attribute name]:[Attribute value]:[Secret key]

urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa
```

Attestations:
```
urn:bap:attest:[Attribute hash]:[Identity key]

urn:bap:attest:42d2396ddfc3dec6acbd96830b844a10b8b2f065e60fbd5238b5267ab086bf4f:1CCWY6EXZwNqbrtW1SXGNFWdwipYT7Ur1Q
```

The URN is hashed using sha256 when used in a transaction sent to the blockchain.

# Creating an identity key

Signing identities in BAP are created by linking a unique identity key with a bitcoin signing address. Identity keys can be any random (!) hex string, but should be at least 64 characters long (256 bits).

Example identity key: `4a59332b7d81c4c68a6edcb1160f4683037a97286b97cc500b5881632e921849z`;

To link this identity key to a signing address, an `ID` transaction is sent to the blockchain:

```
1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT
ID
4a59332b7d81c4c68a6edcb1160f4683037a97286b97cc500b5881632e921849z
1K4c6YXR1ixNLAqrL8nx5HUQAPKbACTwDo
|
15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva
BITCOIN_ECDSA
1WffojxvgpQBmUTigoss7VUdfN45JiiRK
HB6Ye7ekxjKDkblJYL9lX3J2vhY75vl+WfVCq+wW3+y6S7XECkgYwUEVH3WEArRuDb/aVZ8ntLI/D0Yolb1dhD8=
```

The address `1WffojxvgpQBmUTigoss7VUdfN45JiiRK` associated with the first instance of the identity key on-chain, is the identity control address. This address should no be used anywhere, but can be used to destroy the identity, in case the latest linked key has been compromised.

When the signing address is rotated to a new key, a new ID transaction is created, this time signed by the previous address:

```
1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT
ID
4a59332b7d81c4c68a6edcb1160f4683037a97286b97cc500b5881632e921849z
1JfMQDtBKYi6z65M9uF2gxgLv7E8pPR6MA
|
15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva
BITCOIN_ECDSA
1K4c6YXR1ixNLAqrL8nx5HUQAPKbACTwDo
HB6Ye7ekxjKDkblJYL9lX3J2vhY75vl+WfVCq+wW3+y6S7XECkgYwUEVH3WEArRuDb/aVZ8ntLI/D0Yolb1dhD8=
```

In this way, we have created a way to rotate the signing keys for a certain identity as often as we want, with each signing key being immutably saved on the blockchain.

Any signatures done for the identity key should be done using the active key at that time.

To destroy the identity, an ID transaction is sent to 0, signed with the address from the first ever transaction `1WffojxvgpQBmUTigoss7VUdfN45JiiRK`;

```
1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT
ID
4a59332b7d81c4c68a6edcb1160f4683037a97286b97cc500b5881632e921849z
0
|
15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva
BITCOIN_ECDSA
1WffojxvgpQBmUTigoss7VUdfN45JiiRK
HB6Ye7ekxjKDkblJYL9lX3J2vhY75vl+WfVCq+wW3+y6S7XECkgYwUEVH3WEArRuDb/aVZ8ntLI/D0Yolb1dhD8=
```

# Usage in an identity system (BAP-ID)

A BAP identity is defined as an identity key that has attested identity attributes, verified by one or more authorities. These authorities are outside the scope of this description, but are not governed or controlled.

All identity attributes have the following characteristics:

```
urn:bap:id:[Attribute name]:[Attribute value]:[Secret key]
```

Attribute | Description
--------- | ----------
Attribute name | The name of the attribute being described
Attribute value | The value of the attribute being described with the name
Secret key | A unique random number to make sure the entropy of hashing the urn will not cause collision and not allow for dictionary attacks

A user may want to create multiple identities with a varying degree of details available about that identity. Let's take a couple of examples:

Identity 1 (`4a59332b7d81c4c68a6edcb1160f4683037a97286b97cc500b5881632e921849z`):
```
urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa
urn:bap:id:birthday:1990-05-22:e61f23cbbb2284842d77965e2b0e32f0ca890b1894ca4ce652831347ee3596d9
urn:bap:id:over18:1:480ca17ccaacd671b28dc811332525f2f2cd594d8e8e7825de515ce5d52d30e8
urn:bap:id:address:51391 Moorpark Ave #104, San Jose, CA 95129, United States:44d47d2375c8346c7ceeab1904360aaf572b1c940c1bd66ffd5cf88fdf06bc05
urn:bap:id:passportNr:US2343242:9c06a0fb0e2d9cef4928855076255e4df3375e2807cf37bc028ddb282f811ac8
urn:bap:id:passportExpiration:2022-02-23:d61a39afb463b42c3e419463a028deb3e9e2cebf67953864e9f9e7869677e7cb
```

Identity 2 (`b71a658ec49a9cb099fd5d3cf0aafce28f1d464fa6e496f61c8048d8ed56edc1`):
```
urn:bap:id:name:John Doe:6637be9df2e114ce19a287ff48841899ef4a5762a5f9dc47aef62fe4f579bf93
urn:bap:id:email:john.doen@example.com:2864fd138ab1e9ddaaea763c77a45898dac64a26229f9f3d0f2280e4bfa915de
urn:bap:id:over18:1:5f48f9be1644834933cec74a299d109d18f01e77c9552545d2eae4d0c929000b
```

Identity 3 (`10ef2b1bb05185d0dbae41e1bfefe0c2deb2d389f38fe56daa2cc28a9ba82fc7`):
```
urn:bap:id:nickname:Johnny:7a8d693bce6b6c1cf1dd81468a52b69829e465ff9b0762cf77965309df3ad4c8
```

NOTE: The random secret key should not be re-used across identities. Always create a new random secret for each attribute.

## Attesting an identity

Anyone can attest an identity by broadcasting a bitcoin transaction with a signature from their private key of the attributes of the identity.

All attestations have the following characteristics:

```
urn:bap:attest:[Attribute hash]:[Identity key]
```

Attribute | Description
--------- | ----------
Attribute hash | A hash of the urn attribute being attested
Identity key | The unique identity key of the owner of the attestation

Take for example a bank, Banco De Bitcoin, with a known and trusted identity key of `be5dd6cba6f35b0560d9aa85447705f8f22811e6cdc431637b7963876e612cd7` which is linked via an `ID` transaction to `1K4c6YXR1ixNLAqrL8nx5HUQAPKbACTwDo`. To attest that the bank has seen the information in the identity attribute and that it is correct, the bank would sign an attestation with the identity information together with the given identity key.

```
1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT
ATTEST
[Attestation hash]
[Sequence]
|
15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva
[Signature algorithm]
[Address of signer]
[Signature]
```

For the name urn for the Identity 1 (`4a59332b7d81c4c68a6edcb1160f4683037a97286b97cc500b5881632e921849z`) in above example:

- We take the hash of `urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa` = `b17c8e606afcf0d8dca65bdf8f33d275239438116557980203c82b0fae259838`
- Then create an attestation urn for the address: `urn:bap:id:attest:b17c8e606afcf0d8dca65bdf8f33d275239438116557980203c82b0fae259838:4a59332b7d81c4c68a6edcb1160f4683037a97286b97cc500b5881632e921849z`
- Then hash the attestation for our transaction: `5e991865273588e8be0b834b013b7b3b7e4ff2c7517c9fcdf77da84502cebef1`
- Then the attestation is signed with the private key belonging to the trusted authority (with address `1K4c6YXR1ixNLAqrL8nx5HUQAPKbACTwDo`);

```
1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT
ATTEST
5e991865273588e8be0b834b013b7b3b7e4ff2c7517c9fcdf77da84502cebef1
0
|
15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva
BITCOIN_ECDSA
1K4c6YXR1ixNLAqrL8nx5HUQAPKbACTwDo
HB6Ye7ekxjKDkblJYL9lX3J2vhY75vl+WfVCq+wW3+y6S7XECkgYwUEVH3WEArRuDb/aVZ8ntLI/D0Yolb1dhD8=
```

Since the hash of our attestation is always the same, any authority attesting the identity attribute will broadcast a transaction where the 3rd item is the same. In this way it is possible to search (using for instance Planaria) through the blockchain for all attestations of the identity attribute and select the one most trusted.

## Verifying an identity attribute

For a user to prove their identity, that has been verified by a trusted authority, the user does the following.

He shares his identity key `4a59332b7d81c4c68a6edcb1160f4683037a97286b97cc500b5881632e921849z`, the full urn `urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa` and signs a challenge message from the party that request an identity verification.

The receiving party can now verify:
- That the user is the owner of the address `1JfMQDtBKYi6z65M9uF2gxgLv7E8pPR6MA` by verifying the signature
- That the identity `4a59332b7d81c4c68a6edcb1160f4683037a97286b97cc500b5881632e921849z` is linked to the address via an `ID` record
- That the attestation urn has been signed by that latest valid address of Banco De Bitcoin.
- Thereby verifying that the user signing the message has been attested by the bank to have the name `John Doe`.

NOTE: No unneeded sensitive information has been shared and it is not possible to infer any other information from the information sent. The only thing the receiver now knows is that the person doing the signing is called John Doe.

# Using as a Power of Attorney

All users that have an identity and an address registered, should be able to, for instance, give another user temporary rights to sign on their behalf. A Power of Attorney could be defined with the BAP protocol in the following way.

(A power of attorney of this kind is only valid in the real world, but does not allow anyone else to sign anything on-chain)

The Power of Attorney would have the following characteristics:

```
urn:bap:poa:[PoA Attribute]:[Address]:[Secret key]
```
Attribute | Description
--------- | ----------
PoA Attribute | Power of Attorney attribute being handed over to the person with the identity associates with Address
Address | The bitcoin address of the person (or organisation) being handed the PoA
Secret key | A unique random number to make sure the entropy of hashing the urn will not cause collision and not allow for dictionary attacks

PoA attributes:

Attribute | Description
--------- | ----------
real-estate | To buy, sell, rent, or otherwise manage residential, commercial, and personal real estate
business | To invest, trade, and manage any and all business transactions and decisions, as well as handle any claim or litigation matters
finance | To control banking, tax, and government and retirement transactions, as well as living trust and estate decisions
family | To purchase gifts, employ professionals, and to buy, sell or trade any of your personal property
general | This grants the authority to make any decisions that you would be able to if you were personally present

Example, give the bank the Power of Attorney over finances:

For the Identity 1 (`4a59332b7d81c4c68a6edcb1160f4683037a97286b97cc500b5881632e921849z`) given PoA to the bank `be5dd6cba6f35b0560d9aa85447705f8f22811e6cdc431637b7963876e612cd7`:

- We take the hash of `urn:bap:poa:finance:4a59332b7d81c4c68a6edcb1160f4683037a97286b97cc500b5881632e921849z:ef4ef3b8847cf9533cc044dc032269f80ecf6fcbefbd4d6ac81dddc0124f50e7`
- Then hash the poa for the transaction: `77cdec21e1025f85a5cb3744d5515c54783c739b8fa7c72c9e24d83900261d7f`
- Then the poa is signed with the private key belonging to the identity handing over the PoA (with address `1JfMQDtBKYi6z65M9uF2gxgLv7E8pPR6MA`);

```
1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT
ATTEST
77cdec21e1025f85a5cb3744d5515c54783c739b8fa7c72c9e24d83900261d7f
0
|
15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva
BITCOIN_ECDSA
1JfMQDtBKYi6z65M9uF2gxgLv7E8pPR6MA
HB6Ye7ekxjKDkblJYL9lX3J2vhY75vl+WfVCq+wW3+y6S7XECkgYwUEVH3WEArRuDb/aVZ8ntLI/D0Yolb1dhD8=
```

The bank will save the urn and can prove that the PoA is still valid on the blockchain.

The user can always revoke the PoA with a REVOKE transaction.

# Blacklisting

With more and more data being posted to the bitcoin blockchain it becomes ever more important to be able to block data from being viewed on sites offering that service. Especially illegal data needs to be filtered from viewing to prevent liability claims.

A proposed format for blacklisting any type of data could have the following format:
```
urn:bap:blacklist:[type]:[attribute]:[key]
```

## Blacklisting transactions / addresses

Using the blacklisting format, a transaction ID blacklist would be of the following format for a transaction ID:
```
urn:bap:blacklist:bitcoin:tx-id:[Transaction ID]
```

Example, blacklisting transaction ID `9e4b52ca8abe317d246ae2e742898df0956eaf1cc8df7c02154d20c1f55f3f9b`:
```
urn:bap:blacklist:bitcoin:tx-id:9e4b52ca8abe317d246ae2e742898df0956eaf1cc8df7c02154d20c1f55f3f9b
```

The hash of this blacklisting is: `8a6bc20369171516fb9155a10f11caff8a51dbd8ae90c5bf3443fc4c83bdc8e8` 

The attestation looks like:
```
1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT
ATTEST
8a6bc20369171516fb9155a10f11caff8a51dbd8ae90c5bf3443fc4c83bdc8e8
0
|
15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva
BITCOIN_ECDSA
1JfMQDtBKYi6z65M9uF2gxgLv7E8pPR6MA
HB6Ye7ekxjKDkblJYL9lX3J2vhY75vl+WfVCq+wW3+y6S7XECkgYwUEVH3WEArRuDb/aVZ8ntLI/D0Yolb1dhD8=
```

Which would indicate that the ID signing with `1JfMQDtBKYi6z65M9uF2gxgLv7E8pPR6MA` is blacklisting the transaction. This way services can blacklist transactions and publish that on-chain for other services to see.

Third party services could be using this to check whether services they trust are blacklisting transactions and based on that decide not to show them in their viewer. A Simple query of the attestastion hash `8a6bc20369171516fb9155a10f11caff8a51dbd8ae90c5bf3443fc4c83bdc8e8` in a BAP index would return all the services that have blacklisted the transaction.

For a bitcoin address, the blacklist urn would look like:
```
urn:bap:blacklist:bitcoin:address:[Address]
```
Example:
```
urn:bap:blacklist:bitcoin:address:1JfMQDtBKYi6z65M9uF2gxgLv7E8pPR6MA
```

## Blacklisting IP addresses

This blacklisting urn could also be used to signal blacklisting of IP addresses, for instance IP addresses being used by known bot networks.

NOTE: Because IP addresses are personally identifiable information, we need to take more care when hashing these and publishing them on-chain to prevent reverse lookups of the IP addresses.

For IP addresses we could use a concatenation of the idKey of the signing party to add entropy to the hashing:
```
urn:bap:blacklist:ip-address:[IP Address]:[ID key]
```

This would prevent direct lookups and force services to only search for blacklisting by services they trust. A lookup of all attestations and all id's would be an extremly CPU intensive task.

For the Identity 1 (`4a59332b7d81c4c68a6edcb1160f4683037a97286b97cc500b5881632e921849z`) blacklisting IP address `1.1.1.1`:
```
urn:bap:blacklist:ip-address:1.1.1.1:4a59332b7d81c4c68a6edcb1160f4683037a97286b97cc500b5881632e921849z
```

The hash of this blacklisting is: `73df789478993f8f4e100be416811860d6fc2ae208fdfaf256788cd522f21219` 

The attestation looks like:
```
1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT
ATTEST
73df789478993f8f4e100be416811860d6fc2ae208fdfaf256788cd522f21219
0
|
15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva
BITCOIN_ECDSA
1JfMQDtBKYi6z65M9uF2gxgLv7E8pPR6MA
HB6Ye7ekxjKDkblJYL9lX3J2vhY75vl+WfVCq+wW3+y6S7XECkgYwUEVH3WEArRuDb/aVZ8ntLI/D0Yolb1dhD8=
```

A third party service that wants to make use of this information is forced to look through a BAP index in a targeted way, per IP address and for each attesting service separately and is not able to recreate a list of blocked IP addresses.

## Final note on blacklisting

Using attestations for blacklists is a good way of creating one-way blacklists. It's easy to lookup whether some service has blacklisted something (transaction, address, IP address), but it is very hard to create a list of all things a service has blacklisted.

Also because the blacklist attestations look just like any other attestation, the blacklistings can not be identified as such which increases the difficulty of creating a list of  blacklistings of a service.

# Giving consent to access of data

When a website requests data from a user, the user should leave a record on-chain that this data was freely given to the service by the user. The user should also be able to revoke the access to the data, which would imply that the service needs to delete any copy's of the data shared. This is the only way the user is (legally) in charge of what data the service has access to.

A possible way to do this, using BAP:
```
urn:bap:grant:[Attribute hashes]:[Identity key]
```

Example, for a service with identity key `be5dd6cba6f35b0560d9aa85447705f8f22811e6cdc431637b7963876e612cd7`:
```
urn:bap:grant:name,email,nickname:be5dd6cba6f35b0560d9aa85447705f8f22811e6cdc431637b7963876e612cd7
```
This has a hash of `b88bd23005be7e0737f02e67de8b392df834ba27caed1e7774aec77c9dcb85d0`.

The user then needs to attest to this on-chain:
```
1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT
ATTEST
b88bd23005be7e0737f02e67de8b392df834ba27caed1e7774aec77c9dcb85d0
0
|
15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva
BITCOIN_ECDSA
1K4c6YXR1ixNLAqrL8nx5HUQAPKbACTwDo
HB6Ye7ekxjKDkblJYL9lX3J2vhY75vl+WfVCq+wW3+y6S7XECkgYwUEVH3WEArRuDb/aVZ8ntLI/D0Yolb1dhD8=
```

NOTE: this could be given to the service directly as proof of granting access to the data by the user. The service could then put the data on-chain, paying the necessary fees.

The service should be monitoring the blockchain for a revocation of the data sharing grant and remove any data related to this user of the revocation is seen. Alternatively, the user could notify the service of a revocation transaction when made on-chain.

# Revoking an attestation

In rare cases when the attestation needs to be revoked, this can be done using the `REVOKE` keyword. The revocation transaction has exactly the same format as the attestation transaction, except for the REVOKE keyword.

```
1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT
REVOKE
77cdec21e1025f85a5cb3744d5515c54783c739b8fa7c72c9e24d83900261d7f
1
|
15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva
BITCOIN_ECDSA
1JfMQDtBKYi6z65M9uF2gxgLv7E8pPR6MA
HB6Ye7ekxjKDkblJYL9lX3J2vhY75vl+WfVCq+wW3+y6S7XECkgYwUEVH3WEArRuDb/aVZ8ntLI/D0Yolb1dhD8=
```

The sequence number is important here to prevent replays of the transaction.

# Extending the protocol

The protocol could be extended for other use cases, by introducing new keywords (next to ATTEST and REVOKE) or introducing other `urn:bap:...` schemes.
