import bsv from 'bsv';
import Message from 'bsv/message';
import { describe, expect, test } from '@jest/globals';

import { BAP } from '../src';
import { SIGNING_PATH_PREFIX, ENCRYPTION_PATH } from '../src/constants';
import { BAP_ID } from '../src/id';

import { HDPrivateKey, HDPublicKey } from './data/keys';
import fullId from './data/ids.json';
import oldFullId from './data/old-ids.json';

const testBAPInstance = function (bap) {
  // TODO ....
  expect(bap).toMatchObject({});
  expect(bap.getHdPublicKey()).toMatch('xpub');
};
const identityKey = '4a59332b7d81c4c68a6edcb1160f4683037a97286b97cc500b5881632e921849z';

describe('bap', () => {
  test('init', () => {
    const randomHDPrivateKey = bsv.HDPrivateKey.fromRandom().toString();
    const bap = new BAP(randomHDPrivateKey);
    testBAPInstance(bap);
  });

  test('init without key', () => {
    expect(() => {
      const bap = new BAP();
    }).toThrow();
  });

  test('with known key', () => {
    const bap = new BAP(HDPrivateKey);
    testBAPInstance(bap);

    expect(bap.getPublicKey()).toBe('02c23e9fc6a959bb5315159ac7438c5a6bff37c7197326d1060b176e3969d72af5');
    expect(bap.getPublicKey(ENCRYPTION_PATH)).toBe('02fc759e24d922c2d47766710613910c0f40bab7439777af9ad45bff55ec622994');

    expect(bap.getHdPublicKey()).toBe(HDPublicKey);
    expect(bap.getHdPublicKey(ENCRYPTION_PATH)).toBe('xpub6CXbFY2NumUP1dVRRbXiAdj6oRhqK3zQjt1vdzsTBfy3jDLjHMTCCE7AX6fz1KqAag9EPGf52KyCAT9iovKrXZ74BSryrDQ2XBHiawuFfsu');
  });

  test('set BAP_SERVER', () => {
    const bap = new BAP(HDPrivateKey);
    const id = bap.newId();

    expect(bap.BAP_SERVER).toEqual('https://bap.network/api/v1');
    expect(id.BAP_SERVER).toEqual('https://bap.network/api/v1');

    const newServer = 'https://bapdev.legallychained.com/';
    bap.BAP_SERVER = newServer;
    expect(bap.BAP_SERVER).toEqual(newServer);
    expect(id.BAP_SERVER).toEqual(newServer);
  });

  test('set BAP_TOKEN', () => {
    const bap = new BAP(HDPrivateKey);
    const id = bap.newId();

    expect(bap.BAP_TOKEN).toEqual('');
    expect(id.BAP_TOKEN).toEqual('');

    const newToken = 'token_string';
    bap.BAP_TOKEN = newToken;
    expect(bap.BAP_TOKEN).toEqual(newToken);
    expect(id.BAP_TOKEN).toEqual(newToken);

    const tokenAtInit = 'test_token'
    const bap2 = new BAP(HDPrivateKey, tokenAtInit);
    const id2 = bap2.newId();
    expect(bap2.BAP_TOKEN).toEqual(tokenAtInit);
    expect(id2.BAP_TOKEN).toEqual(tokenAtInit);

    const newToken2 = 'token_string2';
    bap2.BAP_TOKEN = newToken2;
    expect(bap2.BAP_TOKEN).toEqual(newToken2);
    expect(id2.BAP_TOKEN).toEqual(newToken2);
  });

  test('import full ID', () => {
    const bap = new BAP(HDPrivateKey);
    bap.importIds(fullId, false);
    testBAPInstance(bap);

    expect(bap.listIds()).toStrictEqual([identityKey]);

    const importedId = bap.getId(identityKey);
    expect(importedId).toBeInstanceOf(BAP_ID);
    expect(importedId.getIdentityKey()).toBe(identityKey);
  });

  test('import OLD full ID', () => {
    const bap = new BAP(HDPrivateKey);
    bap.importIds(oldFullId, false);
    testBAPInstance(bap);

    expect(bap.listIds()).toStrictEqual([identityKey]);

    const importedId = bap.getId(identityKey);
    expect(importedId).toBeInstanceOf(BAP_ID);
    expect(importedId.getIdentityKey()).toBe(identityKey);
  });

  test('export full ID', () => {
    const bap = new BAP(HDPrivateKey);
    bap.importIds(fullId, false);
    testBAPInstance(bap);

    const exportData = bap.exportIds(false);
    expect(exportData).toStrictEqual(fullId);
  });

  test('export/import encrypted ID', () => {
    const bap = new BAP(HDPrivateKey);
    bap.importIds(fullId, false);
    testBAPInstance(bap);

    const encryptedExportData = bap.exportIds();
    expect(typeof encryptedExportData).toBe('string');

    const bap2 = new BAP(HDPrivateKey);
    bap2.importIds(encryptedExportData);
    expect(bap2.listIds()).toStrictEqual([identityKey]);

    const importedId = bap2.getId(identityKey);
    expect(importedId).toBeInstanceOf(BAP_ID);
    expect(importedId.getIdentityKey()).toBe(identityKey);
  });

  test('checkIdBelongs', () => {
    const randomHDPrivateKey = bsv.HDPrivateKey.fromRandom().toString();
    const bap1 = new BAP(randomHDPrivateKey);
    const bap2 = new BAP(HDPrivateKey);

    const id1 = bap1.newId();
    const id2 = bap2.newId();

    expect(bap1.checkIdBelongs(id1)).toBe(true);
    expect(() => {
      bap1.checkIdBelongs(id2);
    }).toThrow();

    expect(bap2.checkIdBelongs(id2)).toBe(true);
    expect(() => {
      bap2.checkIdBelongs(id1);
    }).toThrow();
  });

  test('getId / setId', () => {
    const bap = new BAP(HDPrivateKey);
    const newId = bap.newId();
    const idKey = newId.getIdentityKey();
    bap.setId(newId);

    expect(bap.getId('test')).toEqual(null);
    expect(bap.getId(idKey).identityKey).toStrictEqual(idKey);

    expect(() => {
      bap.setId({});
    }).toThrow();
  });

  test('listIds', () => {
    const randomHDPrivateKey = bsv.HDPrivateKey.fromRandom().toString();
    const bap = new BAP(randomHDPrivateKey);
    expect(bap.listIds()).toStrictEqual([]);

    const newId = bap.newId();
    const idKey = newId.getIdentityKey();
    bap.setId(newId);
    expect(bap.listIds()).toStrictEqual([idKey]);
  });

  test('newId', () => {
    const randomHDPrivateKey = bsv.HDPrivateKey.fromRandom().toString();
    const bap = new BAP(randomHDPrivateKey);
    const newId = bap.newId();
    expect(newId).toBeInstanceOf(BAP_ID);
    expect(bap.checkIdBelongs(newId)).toBe(true);
    expect(newId.rootPath).toBe(`${SIGNING_PATH_PREFIX}/0'/0'/0'`);
    expect(newId.currentPath).toBe(`${SIGNING_PATH_PREFIX}/0'/0'/1'`);

    const newId2 = bap.newId('/123/124/0');
    expect(newId2).toBeInstanceOf(BAP_ID);
    expect(bap.checkIdBelongs(newId2)).toBe(true);
    expect(newId2.rootPath).toBe(`${SIGNING_PATH_PREFIX}/123/124/0`);
    expect(newId2.currentPath).toBe(`${SIGNING_PATH_PREFIX}/123/124/1`);

    // Hardened path given
    const newId3 = bap.newId(`/123'/124'/0`);
    expect(newId3).toBeInstanceOf(BAP_ID);
    expect(bap.checkIdBelongs(newId3)).toBe(true);
    expect(newId3.rootPath).toBe(`${SIGNING_PATH_PREFIX}/123'/124'/0`);
    expect(newId3.currentPath).toBe(`${SIGNING_PATH_PREFIX}/123'/124'/1`);

    // Hardened full path given
    const newId4 = bap.newId(`/123'/124'/0'`);
    expect(newId4).toBeInstanceOf(BAP_ID);
    expect(bap.checkIdBelongs(newId4)).toBe(true);
    expect(newId4.rootPath).toBe(`${SIGNING_PATH_PREFIX}/123'/124'/0'`);
    expect(newId4.currentPath).toBe(`${SIGNING_PATH_PREFIX}/123'/124'/1'`);

    expect(() => {
      const newId4 = bap.newId('/123erg/124ggg/0');
    }).toThrow();
  });

  test('verifyAttestationWithAIP', () => {
    // test in id
    const bap = new BAP(HDPrivateKey);
    expect(() => {
      bap.verifyAttestationWithAIP([]);
    }).toThrow();
  });

  test('import full BAP doc', () => {
    const fullBap = new BAP(HDPrivateKey);
    fullBap.importIds(fullId, false);

    const bapId = fullBap.getId(identityKey);
    expect(bapId.getAttribute('name').value).toBe('John Doe');
    expect(bapId.getAttribute('name').nonce).toBe('e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa');
    expect(bapId.getAttributeUrn('name')).toBe('urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa');
  });

  test('sign attestation with AIP', () => {
    const bap = new BAP(HDPrivateKey);
    bap.importIds(fullId, false);

    const userId = new BAP_ID(bsv.HDPrivateKey(HDPrivateKey), {
      "name": {
        "value": "John Doe",
        "nonce": "e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa"
      },
    });
    const attestationHash = userId.getAttestationHash('name');
    expect(attestationHash).toBe('d6cbf280ad7515e549c7b154a02555fff3eeb05c6b245039813d39d3c0397b4a');

    // create a signing transaction of the user's hash with our own identity key
    const transaction = bap.signAttestationWithAIP(attestationHash, identityKey);
    expect(transaction.length).toBe(10);
    const verify = bap.verifyAttestationWithAIP(transaction);
    expect(verify.verified).toBe(true);
  });

  test('sign attestation with AIP and data', () => {
    const bap = new BAP(HDPrivateKey);
    bap.importIds(fullId, false);

    const userId = new BAP_ID(bsv.HDPrivateKey(HDPrivateKey), {
      "name": {
        "value": "John Doe",
        "nonce": "e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa"
      },
    });
    const attestationHash = userId.getAttestationHash('name');
    expect(attestationHash).toBe('d6cbf280ad7515e549c7b154a02555fff3eeb05c6b245039813d39d3c0397b4a');

    // create a signing transaction of the user's hash with our own identity key
    const dataString = 'This is a test string to add to the attestation';
    const transaction = bap.signAttestationWithAIP(attestationHash, identityKey, 0, dataString);
    expect(transaction.length).toBe(15);
    const verify = bap.verifyAttestationWithAIP(transaction);
    expect(verify.verified).toBe(true);
  });

  test('lastIdPath', () => {
    const fullBap = new BAP(HDPrivateKey);
    fullBap.importIds(fullId, false);
    expect(fullBap.lastIdPath).toBe('/26562456/876543/345346');

    const newId = fullBap.newId();
    const idKey = newId.getIdentityKey();
    expect(fullBap.lastIdPath).toBe('/26562456/876544/0');

    fullBap.removeId(idKey);
    expect(fullBap.lastIdPath).toBe('/26562456/876544/0');

    const newId2 = fullBap.newId();
    const idKey2 = newId2.getIdentityKey();
    expect(fullBap.lastIdPath).toBe('/26562456/876545/0');

    fullBap.removeId(idKey2);
    expect(fullBap.lastIdPath).toBe('/26562456/876545/0');

    const newId3 = fullBap.newId();
    expect(fullBap.lastIdPath).toBe('/26562456/876546/0');

    const idKeys = fullBap.listIds();
    expect(idKeys.length).toBe(2);
  });

  /*
  test('verifyChallengeSignature', () => {
    const privateKey = bsv.PrivateKey.fromRandom();
    const address = privateKey.publicKey.toAddress().toString();
    const message = 'test message';
    const signature = Message(message).sign(privateKey);

    const bap = new BAP(HDPrivateKey);
    const result = bap.verifyChallengeSignature(
      identityKey,
      address,
      message,
      signature
    )
    expect(result).toBe(true);
  });

   */
});
