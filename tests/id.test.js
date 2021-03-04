import { describe, expect, beforeEach, afterEach, test, } from '@jest/globals';
import { BAP } from '../src';
import { BAP_ID } from '../src/id';
import { HDPrivateKey } from './data/keys';
import bsv from 'bsv';
import {
  BAP_BITCOM_ADDRESS_HEX,
  AIP_BITCOM_ADDRESS_HEX, SIGNING_PATH_PREFIX,
} from '../src/constants';

const identityAttributes = {
  name: {
    value: 'John Doe',
    nonce: 'e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa',
  },
  email: {
    value: 'john.doe@example.com',
    nonce: '2864fd138ab1e9ddaaea763c77a45898dac64a26229f9f3d0f2280e4bfa915de',
  },
};
const identityAttributeStrings = `
    urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa
    urn:bap:id:email:john.doe@example.com:2864fd138ab1e9ddaaea763c77a45898dac64a26229f9f3d0f2280e4bfa915de
`;

let bap;

describe('bap-id', () => {
  beforeEach(() => {
    bap = new BAP(HDPrivateKey);
  });

  test('new id', () => {
    const bapId = bap.newId();

    const identityKey = bapId.getIdentityKey();
    expect(typeof identityKey).toBe('string');
    expect(identityKey).toHaveLength(27);
    expect(bapId.getAttributes()).toMatchObject({});
  });

  test('new id with known key', () => {
    const userId = new BAP_ID(bsv.HDPrivateKey(HDPrivateKey));
    const rootAddress = userId.rootAddress;
    const identityKey = userId.getIdentityKey();
    expect(rootAddress).toBe('1CSJiMMYzfW8gbhXXNYyEJ1NsWJohLXyet');
    expect(identityKey).toBe('2cWvSXKfFQScCgDFssRPKvDLjNYx');
  });

  test('new id with seeded keys', () => {
    const userId = new BAP_ID(bsv.HDPrivateKey(HDPrivateKey), {}, 'test');
    const rootAddress = userId.rootAddress;
    const identityKey = userId.getIdentityKey();
    expect(rootAddress).toBe('189oxMiD6wFA4nD38CkoWBKragxXUfw26J');
    expect(identityKey).toBe('ffw3VszEVByph2DuHUiswEMNjRm');

    const userId2 = new BAP_ID(bsv.HDPrivateKey(HDPrivateKey), {}, 'testing 123');
    const rootAddress2 = userId2.rootAddress;
    const identityKey2 = userId2.getIdentityKey();
    expect(rootAddress2).toBe('18zrzzv2Nieve7QAj2AwGDcPYyBziz8vWk');
    expect(identityKey2).toBe('2UKj9321g9pDExCjL7dPhXMtM326');
  });

  test('set BAP_SERVER', () => {
    const bap = new BAP(HDPrivateKey);
    const id = bap.newId();
    expect(id.BAP_SERVER).toBe('https://bap.network/api/v1');

    const newServer = 'https://bapdev.legallychained.com/';
    id.BAP_SERVER = newServer;
    expect(id.BAP_SERVER).toBe(newServer);
  });

  test('parseAttributes', () => {
    const bapId = bap.newId();
    const parsed = bapId.parseAttributes(identityAttributes);
    expect(parsed).toStrictEqual(identityAttributes);

    const parsed2 = bapId.parseAttributes(identityAttributeStrings);
    expect(parsed2).toStrictEqual(identityAttributes);
  });

  test('parseStringUrns', () => {
    const bapId = bap.newId();
    const parsed = bapId.parseStringUrns(identityAttributeStrings);
    expect(parsed).toStrictEqual(identityAttributes);

    expect(() => {
      bapId.parseStringUrns({value: 'John Doe', nonce: ''});
    }).toThrow();
  });

  test('attributes', () => {
    const bapId = bap.newId(false, identityAttributes);
    bapId.addAttribute('birthday', '1990-05-22'); // nonce will be automatically generated
    bapId.addAttribute('over18', '1', 'ca17ccaacd671b28dc811332525f2f2cd594d8e8e7825de515ce5d52d30e8');

    expect(bapId.getAttribute('name').value).toBe('John Doe');
    expect(bapId.getAttribute('name').nonce).toBe('e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa');

    expect(bapId.getAttribute('birthday').value).toBe('1990-05-22');
    expect(typeof bapId.getAttribute('birthday').nonce).toBe('string');
    expect(bapId.getAttribute('birthday').nonce).toHaveLength(64);

    expect(bapId.getAttribute('over18').value).toBe('1');
    expect(bapId.getAttribute('over18').nonce).toBe('ca17ccaacd671b28dc811332525f2f2cd594d8e8e7825de515ce5d52d30e8');

    expect(bapId.getAttribute('over21')).toBe(null);
  });

  test('getAttributeUrns', () => {
    const bapId = bap.newId(false, identityAttributes);

    expect(bapId.getAttributeUrn('name')).toBe('urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa');
    expect(bapId.getAttributeUrn('over21')).toBe(null);

    const attributeStrings = bapId.getAttributeUrns();
    expect(attributeStrings).toBe(`urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa
urn:bap:id:email:john.doe@example.com:2864fd138ab1e9ddaaea763c77a45898dac64a26229f9f3d0f2280e4bfa915de
`);
  });

  test('incrementPath', () => {
    const randomHDPrivateKey = bsv.HDPrivateKey.fromRandom();
    const bapId = new BAP_ID(randomHDPrivateKey);

    expect(bapId.currentPath).toBe(`${SIGNING_PATH_PREFIX}/0/0/1`);
    bapId.incrementPath();
    expect(bapId.previousPath).toBe(`${SIGNING_PATH_PREFIX}/0/0/1`);
    expect(bapId.currentPath).toBe(`${SIGNING_PATH_PREFIX}/0/0/2`);
    bapId.incrementPath();
    expect(bapId.previousPath).toBe(`${SIGNING_PATH_PREFIX}/0/0/2`);
    expect(bapId.currentPath).toBe(`${SIGNING_PATH_PREFIX}/0/0/3`);
    bapId.incrementPath();
    expect(bapId.previousPath).toBe(`${SIGNING_PATH_PREFIX}/0/0/3`);
    expect(bapId.currentPath).toBe(`${SIGNING_PATH_PREFIX}/0/0/4`);
  });

  test('signingPath', () => {
    const bapId = bap.newId();
    expect(bapId.rootPath).toBe("m/424150'/0'/0'/0'/0'/0'");
    expect(bapId.currentPath).toBe("m/424150'/0'/0'/0'/0'/1'");

    bapId.currentPath = '/0/0/2';
    expect(bapId.currentPath).toBe("m/424150'/0'/0'/0/0/2");

    expect(() => {
      bapId.rootPath = 'test';
    }).toThrow();
    expect(() => {
      bapId.currentPath = 'test';
    }).toThrow();
  });

  test('getAttestation / Hash', () => {
    const bapId = bap.newId(false, identityAttributes);
    const urn = bapId.getAttributeUrn('name');
    expect(urn).toBe('urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa');
    const attestation = bapId.getAttestation(urn);
    expect(attestation).toBe('bap:attest:b17c8e606afcf0d8dca65bdf8f33d275239438116557980203c82b0fae259838:GbPKb7tQpfZDut9mJnBm5BMtGqu');

    const hash = bapId.getAttestationHash('name');
    expect(hash).toBe('bc91964394e81cb0fc0a0cad53894456711e2f7e4626ce3977de0a92abdded70');
  });

  test('getInitialIdTransaction', () => {
    const bapId = bap.newId(false, identityAttributes);
    const tx = bapId.getInitialIdTransaction();
    expect('0x' + tx[0]).toBe(BAP_BITCOM_ADDRESS_HEX);
    expect(tx[1]).toBe(Buffer.from('ID').toString('hex'));
    expect(tx[2]).toBe(Buffer.from(bapId.getIdentityKey()).toString('hex'));
    expect(tx[3]).toBe(Buffer.from(bapId.getAddress(bapId.currentPath)).toString('hex'));
    expect(tx[4]).toBe(Buffer.from('|').toString('hex'));
    expect('0x' + tx[5]).toBe(AIP_BITCOM_ADDRESS_HEX);
    expect(tx[6]).toBe(Buffer.from('BITCOIN_ECDSA').toString('hex'));
    expect(tx[7]).toBe(Buffer.from(bapId.getAddress(bapId.rootPath)).toString('hex'));
    expect(typeof tx[8]).toBe('string');
  });

  test('encryption', () => {
    const bapId = bap.newId(false, identityAttributes);
    const pubKey = bapId.getEncryptionPublicKey();
    expect(pubKey).toBe('02a257adfbba04a25a7c37600209a0926aa264428b2d3d2b17fa97cf9c31b87cdf');

    const testData = 'This is a test we are going to encrypt';
    const ciphertext = bapId.encrypt(testData);
    expect(typeof ciphertext).toBe('string');
    expect(testData === ciphertext).toBe(false);

    const decrypted = bapId.decrypt(ciphertext);
    expect(testData === decrypted).toBe(true);
  });
});
