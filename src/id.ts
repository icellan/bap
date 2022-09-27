import bsv from 'bsv';
// @ts-ignore
import ECIES from 'bsv/ecies';
// @ts-ignore
import Message from 'bsv/message';
import {
  MAX_INT,
  SIGNING_PATH_PREFIX,
  BAP_SERVER,
  BAP_BITCOM_ADDRESS,
  AIP_BITCOM_ADDRESS, ENCRYPTION_PATH,
} from './constants';
import { Utils } from './utils';
import {Identity} from "./interface";

/**
 * BAP_ID class
 *
 * This class should be used in conjunction with the BAP class
 *
 * @type {BAP_ID}
 */
class BAP_ID {
  #HDPrivateKey: bsv.HDPrivateKey;
  #BAP_SERVER: string = BAP_SERVER;
  #BAP_TOKEN = '';
  #rootPath: string;
  #previousPath: string;
  #currentPath: string;
  #idSeed: string;

  idName: string;
  description: string;

  rootAddress: string;
  identityKey: string;
  identityAttributes: { [key: string]: any }

  constructor(HDPrivateKey: bsv.HDPrivateKey, identityAttributes: { [key: string]: any } = {}, idSeed = '') {
    this.#idSeed = idSeed;
    if (idSeed) {
      // create a new HDPrivateKey based on the seed
      const seedHex = bsv.crypto.Hash.sha256(Buffer.from(idSeed)).toString('hex');
      const seedPath = Utils.getSigningPathFromHex(seedHex);
      this.#HDPrivateKey = HDPrivateKey.deriveChild(seedPath);
    } else {
      this.#HDPrivateKey = HDPrivateKey;
    }

    this.idName = 'ID 1';
    this.description = '';

    this.#rootPath = `${SIGNING_PATH_PREFIX}/0/0/0`;
    this.#previousPath = `${SIGNING_PATH_PREFIX}/0/0/0`;
    this.#currentPath = `${SIGNING_PATH_PREFIX}/0/0/1`;

    const rootChild = this.#HDPrivateKey.deriveChild(this.#rootPath);
    this.rootAddress = rootChild.privateKey.publicKey.toAddress().toString();
    this.identityKey = this.deriveIdentityKey(this.rootAddress);

    // unlink the object
    identityAttributes = { ...identityAttributes };
    this.identityAttributes = this.parseAttributes(identityAttributes);
  }

  set BAP_SERVER(bapServer) {
    this.#BAP_SERVER = bapServer;
  }

  get BAP_SERVER(): string {
    return this.#BAP_SERVER;
  }

  set BAP_TOKEN(token) {
    this.#BAP_TOKEN = token;
  }

  get BAP_TOKEN(): string {
    return this.#BAP_TOKEN;
  }

  deriveIdentityKey(address: string): string {
    const rootAddressHash = bsv.crypto.Hash.sha256(Buffer.from(address));
    // @ts-ignore
    return bsv.encoding.Base58(bsv.crypto.Hash.ripemd160(rootAddressHash)).toString();
  }

  /**
   * Helper function to parse identity attributes
   *
   * @param identityAttributes
   * @returns {{}}
   */
  parseAttributes(identityAttributes: { [key: string]: any } | string): { [key: string]: any } {
    if (typeof identityAttributes === 'string') {
      return this.parseStringUrns(identityAttributes);
    }

    Object.keys(identityAttributes).forEach((key) => {
      if (
        !identityAttributes[key].hasOwnProperty('value')
        || !identityAttributes[key].hasOwnProperty('nonce')
      ) {
        throw new Error('Invalid identity attribute');
      }
    });

    return identityAttributes || {};
  }

  /**
   * Parse a text of urn string into identity attributes
   *
   * urn:bap:id:name:John Doe:e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa
   * urn:bap:id:birthday:1990-05-22:e61f23cbbb2284842d77965e2b0e32f0ca890b1894ca4ce652831347ee3596d9
   * urn:bap:id:over18:1:480ca17ccaacd671b28dc811332525f2f2cd594d8e8e7825de515ce5d52d30e8
   *
   * @param urnIdentityAttributes
   */
  parseStringUrns(urnIdentityAttributes: string): { [key: string]: any } {
    const identityAttributes: { [key: string]: any } = {};
    urnIdentityAttributes.replace(/^\s+/g, '').replace(/\r/gm, '')
      .split('\n')
      .forEach((line) => {
        // remove any whitespace from the string (trim)
        line = line.replace(/^\s+/g, '').replace(/\s+$/g, '');
        const urn = line.split(':');
        if (urn[0] === 'urn' && urn[1] === 'bap' && urn[2] === 'id' && urn[3] && urn[4] && urn[5]) {
          identityAttributes[urn[3]] = {
            value: urn[4],
            nonce: urn[5],
          };
        }
      });

    return identityAttributes;
  }

  /**
   * Returns the identity key
   *
   * @returns {*|string}
   */
  getIdentityKey(): string {
    return this.identityKey;
  }

  /**
   * Returns all the attributes in the identity
   *
   * @returns {*}
   */
  getAttributes(): { [key: string]: any } {
    return this.identityAttributes;
  }

  /**
   * Get the value of the given attribute
   *
   * @param attributeName
   * @returns {{}|null}
   */
  getAttribute(attributeName: string): any {
    if (this.identityAttributes.hasOwnProperty(attributeName)) {
      return this.identityAttributes[attributeName];
    }

    return null;
  }

  /**
   * Set the value of the given attribute
   *
   * If an empty value ('' || null || false) is given, the attribute is removed from the ID
   *
   * @param attributeName string
   * @param attributeValue any
   * @returns {{}|null}
   */
  setAttribute(attributeName: string, attributeValue: any): void {
    if (attributeValue) {
      if (this.identityAttributes.hasOwnProperty(attributeName)) {
        this.identityAttributes[attributeName].value = attributeValue;
      } else {
        this.addAttribute(attributeName, attributeValue);
      }
    }
  }

  /**
   * Unset the given attribute from the ID
   *
   * @param attributeName
   * @returns {{}|null}
   */
  unsetAttribute(attributeName: string): void {
    delete this.identityAttributes[attributeName];
  }

  /**
   * Get all attribute urn's for this id
   *
   * @returns {string}
   */
  getAttributeUrns(): string {
    let urns = '';
    Object.keys(this.identityAttributes)
      .forEach((key) => {
        const urn = this.getAttributeUrn(key);
        if (urn) {
          urns += `${urn}\n`;
        }
      });

    return urns;
  }

  /**
   * Create an return the attribute urn for the given attribute
   *
   * @param attributeName
   * @returns {string|null}
   */
  getAttributeUrn(attributeName: string) {
    const attribute = this.identityAttributes[attributeName];
    if (attribute) {
      return `urn:bap:id:${attributeName}:${attribute.value}:${attribute.nonce}`;
    }

    return null;
  }

  /**
   * Add an attribute to this identity
   *
   * @param attributeName
   * @param value
   * @param nonce
   */
  addAttribute(attributeName: string, value: any, nonce = ''): void {
    if (!nonce) {
      nonce = Utils.getRandomString();
    }

    this.identityAttributes[attributeName] = {
      value,
      nonce,
    };
  }

  /**
   * This should be called with the last part of the signing path (/.../.../...)
   * This library assumes the first part is m/424150'/0'/0' as defined at the top of this file
   *
   * @param path The second path of the signing path in the format [0-9]{0,9}/[0-9]{0,9}/[0-9]{0,9}
   */
  set rootPath(path) {
    if (this.#HDPrivateKey) {
      if (path.split('/').length < 5) {
        path = `${SIGNING_PATH_PREFIX}${path}`;
      }

      if (!this.validatePath(path)) {
        throw new Error('invalid signing path given ' + path);
      }

      this.#rootPath = path;

      const derivedChild = this.#HDPrivateKey.deriveChild(path);
      this.rootAddress = derivedChild.publicKey.toAddress().toString();
      // Identity keys should be derivatives of the root address - this allows checking
      // of the creation transaction
      this.identityKey = this.deriveIdentityKey(this.rootAddress);

      // we also set this previousPath / currentPath to the root as we seem to be (re)setting this ID
      this.#previousPath = path;
      this.#currentPath = path;
    }
  }

  get rootPath(): string {
    return this.#rootPath;
  }

  getRootPath(): string {
    return this.#rootPath;
  }

  /**
   * This should be called with the last part of the signing path (/.../.../...)
   * This library assumes the first part is m/424150'/0'/0' as defined at the top of this file
   *
   * @param path The second path of the signing path in the format [0-9]{0,9}/[0-9]{0,9}/[0-9]{0,9}
   */
  set currentPath(path) {
    if (path.split('/').length < 5) {
      path = `${SIGNING_PATH_PREFIX}${path}`;
    }

    if (!this.validatePath(path)) {
      throw new Error('invalid signing path given');
    }

    this.#previousPath = this.#currentPath;
    this.#currentPath = path;
  }

  get currentPath(): string {
    return this.#currentPath;
  }

  get previousPath(): string {
    return this.#previousPath;
  }

  /**
   * This can be used to break the deterministic way child keys are created to make it harder for
   * an attacker to steal the identites when the root key is compromised. This does however require
   * the seeds to be stored at all times. If the seed is lost, the identity will not be recoverable.
   */
  get idSeed(): string {
    return this.#idSeed;
  }

  /**
   * Increment current path to a new path
   *
   * @returns {*}
   */
  incrementPath(): void {
    this.currentPath = Utils.getNextPath(this.currentPath);
  }

  /**
   * Check whether the given path is a valid path for use with this class
   * The signing paths used here always have a length of 3
   *
   * @param path The last part of the signing path (example "/0/0/1")
   * @returns {boolean}
   */
  validatePath(path: string) {
    /* eslint-disable max-len */
    if (path.match(/\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?\/[0-9]{1,10}'?/)) {
      const pathValues = path.split('/');
      if (pathValues.length === 7
        && Number(pathValues[1].replace('\'', '')) <= MAX_INT
        && Number(pathValues[2].replace('\'', '')) <= MAX_INT
        && Number(pathValues[3].replace('\'', '')) <= MAX_INT
        && Number(pathValues[4].replace('\'', '')) <= MAX_INT
        && Number(pathValues[5].replace('\'', '')) <= MAX_INT
        && Number(pathValues[6].replace('\'', '')) <= MAX_INT
      ) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get the OP_RETURN for the initial ID transaction (signed with root address)
   *
   * @returns {[]}
   */
  getInitialIdTransaction() {
    return this.getIdTransaction(this.#rootPath);
  }

  /**
   * Get the OP_RETURN for the ID transaction of the current address / path
   *
   * @returns {[]}
   */
  getIdTransaction(previousPath = '') {
    if (this.#currentPath === this.#rootPath) {
      throw new Error('Current path equals rootPath. ID was probably not initialized properly');
    }

    const opReturn = [
      Buffer.from(BAP_BITCOM_ADDRESS).toString('hex'),
      Buffer.from('ID').toString('hex'),
      Buffer.from(this.identityKey).toString('hex'),
      Buffer.from(this.getCurrentAddress()).toString('hex'),
    ];

    previousPath = previousPath || this.#previousPath;

    return this.signOpReturnWithAIP(opReturn, previousPath);
  }

  /**
   * Get address for given path
   *
   * @param path
   * @returns {*}
   */
  getAddress(path: string): string {
    const derivedChild = this.#HDPrivateKey.deriveChild(path);
    return derivedChild.privateKey.publicKey.toAddress().toString();
  }

  /**
   * Get current signing address
   *
   * @returns {*}
   */
  getCurrentAddress(): string {
    return this.getAddress(this.#currentPath);
  }

  /**
   * Get the public key for encrypting data for this identity
   */
  getEncryptionPublicKey(): string {
    const HDPrivateKey = this.#HDPrivateKey.deriveChild(this.#rootPath);
    const encryptionKey = HDPrivateKey.deriveChild(ENCRYPTION_PATH).privateKey;
    // @ts-ignore
    return encryptionKey.publicKey.toString('hex');
  }

  /**
   * Encrypt the given string data with the identity encryption key
   * @param stringData
   * @return string Base64
   */
  encrypt(stringData: string): string {
    const publicKey = bsv.PublicKey.fromHex(this.getEncryptionPublicKey());
    const ecies = new ECIES();
    ecies.publicKey(publicKey);
    return ecies.encrypt(stringData).toString('base64');
  }

  /**
   * Decrypt the given ciphertext with the identity encryption key
   * @param ciphertext
   */
  decrypt(ciphertext: string): string {
    const HDPrivateKey = this.#HDPrivateKey.deriveChild(this.#rootPath);
    const encryptionKey = HDPrivateKey.deriveChild(ENCRYPTION_PATH).privateKey;
    const ecies = new ECIES();
    ecies.privateKey(encryptionKey);
    return ecies.decrypt(Buffer.from(ciphertext, 'base64')).toString();
  }

  /**
   * Get an attestation string for the given urn for this identity
   *
   * @param urn
   * @returns {string}
   */
  getAttestation(urn: string) {
    const urnHash = bsv.crypto.Hash.sha256(Buffer.from(urn));
    return `bap:attest:${urnHash.toString('hex')}:${this.getIdentityKey()}`;
  }

  /**
   * Generate and return the attestation hash for the given attribute of this identity
   *
   * @param attribute Attribute name (name, email etc.)
   * @returns {string}
   */
  getAttestationHash(attribute: string) {
    const urn = this.getAttributeUrn(attribute);
    if (!urn) return null;

    const attestation = this.getAttestation(urn);
    const attestationHash = bsv.crypto.Hash.sha256(Buffer.from(attestation));

    return attestationHash.toString('hex');
  }

  /**
   * Sign a message with the current signing address of this identity
   *
   * @param message
   * @param signingPath
   * @returns {{address, signature}}
   */
  signMessage(message: string | Buffer, signingPath = '') {
    if (!(message instanceof Buffer)) {
      message = Buffer.from(message);
    }

    signingPath = signingPath || this.#currentPath;
    const derivedChild = this.#HDPrivateKey.deriveChild(signingPath);
    const address = derivedChild.privateKey.publicKey.toAddress().toString();
    const signature = Message(message).sign(derivedChild.privateKey);

    return { address, signature };
  }

  /**
   * Sign a message using a key based on the given string seed
   *
   * This works by creating a private key from the root key of this identity. It will always
   * work with the rootPath / rootKey, to be deterministic. It will not change even if the keys
   * are rotated for this ID.
   *
   * This is used in for instance deterministic login systems, that do not support BAP.
   *
   * @param message
   * @param seed {string} String seed that will be used to generate a path
   */
  signMessageWithSeed(message: string, seed: string): { address: string, signature: string } {
    const pathHex = bsv.crypto.Hash.sha256(Buffer.from(seed)).toString('hex');
    const path = Utils.getSigningPathFromHex(pathHex);

    const HDPrivateKey = this.#HDPrivateKey.deriveChild(this.#rootPath);
    const derivedChild = HDPrivateKey.deriveChild(path);
    const address = derivedChild.privateKey.publicKey.toAddress().toString();
    const signature = Message(message).sign(derivedChild.privateKey);

    return { address, signature };
  }

  /**
   * Sign an op_return hex array with AIP
   * @param opReturn {array}
   * @param signingPath {string}
   * @param outputType {string}
   * @return {[]}
   */
  signOpReturnWithAIP(opReturn: string[], signingPath = '', outputType: BufferEncoding = 'hex'): string[] {
    const aipMessageBuffer = this.getAIPMessageBuffer(opReturn);
    const { address, signature } = this.signMessage(aipMessageBuffer, signingPath);

    return opReturn.concat([
      Buffer.from('|').toString(outputType),
      Buffer.from(AIP_BITCOM_ADDRESS).toString(outputType),
      Buffer.from('BITCOIN_ECDSA').toString(outputType),
      Buffer.from(address).toString(outputType),
      Buffer.from(signature, 'base64').toString(outputType),
    ]);
  }

  /**
   * Construct an AIP buffer from the op return data
   * @param opReturn
   * @returns {Buffer}
   */
  getAIPMessageBuffer(opReturn: string[]): Buffer {
    const buffers = [];
    if (opReturn[0].replace('0x', '') !== '6a') {
      // include OP_RETURN in constructing the signature buffer
      buffers.push(Buffer.from('6a', 'hex'));
    }
    opReturn.forEach((op) => {
      buffers.push(Buffer.from(op.replace('0x', ''), 'hex'));
    });
    // add a trailing "|" - this is the AIP way
    buffers.push(Buffer.from('|'));

    return Buffer.concat([...buffers]);
  }

  /**
   * Get all signing keys for this identity
   */
  async getIdSigningKeys(): Promise<any> {
    const signingKeys = await this.getApiData('/signing-keys', {
      idKey: this.identityKey,
    });
    console.log('getIdSigningKeys', signingKeys);

    return signingKeys;
  }

  /**
   * Get all attestations for the given attribute
   *
   * @param attribute
   */
  async getAttributeAttestations(attribute: string): Promise<any> {
    // This function needs to make a call to a BAP server to get all the attestations for this
    // identity for the given attribute
    const attestationHash = this.getAttestationHash(attribute);

    // get all BAP ATTEST records for the given attestationHash
    const attestations = await this.getApiData('/attestations', {
      hash: attestationHash,
    });
    console.log('getAttestations', attribute, attestationHash, attestations);

    return attestations;
  }

  /**
   * Helper function to get attestation from a BAP API server
   *
   * @param apiUrl
   * @param apiData
   * @returns {Promise<any>}
   */
  async getApiData(apiUrl: string, apiData: any): Promise<any> {
    const url = `${this.#BAP_SERVER}${apiUrl}`;
    const response = await fetch(url, {
      method: 'post',
      headers: {
        'Content-type': 'application/json; charset=utf-8',
        token: this.#BAP_TOKEN,
        format: 'json',
      },
      body: JSON.stringify(apiData),
    });
    return response.json();
  }

  /**
   * Import an identity from a JSON object
   *
   * @param identity{{}}
   */
  import(identity: Identity): void {
    this.idName = identity.name;
    this.description = identity.description || '';
    this.identityKey = identity.identityKey;
    this.#rootPath = identity.rootPath;
    this.rootAddress = identity.rootAddress;
    this.#previousPath = identity.previousPath;
    this.#currentPath = identity.currentPath;
    this.#idSeed = identity.idSeed || '';
    this.identityAttributes = this.parseAttributes(identity.identityAttributes);
  }

  /**
   * Export this identity to a JSON object
   * @returns {{}}
   */
  export(): Identity {
    return {
      name: this.idName,
      description: this.description,
      identityKey: this.identityKey,
      rootPath: this.#rootPath,
      rootAddress: this.rootAddress,
      previousPath: this.#previousPath,
      currentPath: this.#currentPath,
      idSeed: this.#idSeed,
      identityAttributes: this.getAttributes(),
      lastIdPath: ''
    };
  }
}

export {
  BAP_ID,
}
