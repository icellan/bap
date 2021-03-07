import bsv from 'bsv';
import Message from 'bsv/message';
import ECIES from 'bsv/ecies';
import 'node-fetch';

import { Utils } from './utils';
import { BAP_ID } from './id';
import {
  ENCRYPTION_PATH,
  BAP_SERVER,
  BAP_BITCOM_ADDRESS,
  BAP_BITCOM_ADDRESS_HEX,
  AIP_BITCOM_ADDRESS,
} from './constants';

/**
 * BAP class
 *
 * Creates an instance of the BAP class and uses the given HDPrivateKey for all BAP operations.
 *
 * @param HDPrivateKey
 */
export const BAP = class {
  #HDPrivateKey = null;

  #ids = {};

  #BAP_SERVER = BAP_SERVER;

  #BAP_TOKEN = '';

  #lastIdPath = '';

  constructor(HDPrivateKey, token = false) {
    if (!HDPrivateKey) {
      throw new Error('No HDPrivateKey given');
    } else {
      this.#HDPrivateKey = bsv.HDPrivateKey(HDPrivateKey);
    }

    if (token) {
      this.#BAP_TOKEN = token;
    }
  }

  get lastIdPath() {
    return this.#lastIdPath;
  }

  /**
   * Get the public key of the given childPath, or of the current HDPrivateKey of childPath is empty
   *
   * @param childPath Full derivation path for this child
   * @returns {*}
   */
  getPublicKey(childPath = false) {
    if (childPath) {
      return this.#HDPrivateKey.deriveChild(childPath).publicKey.toString();
    }

    return this.#HDPrivateKey.publicKey.toString();
  }

  /**
   * Get the public key of the given childPath, or of the current HDPrivateKey of childPath is empty
   *
   * @param childPath Full derivation path for this child
   * @returns {*}
   */
  getHdPublicKey(childPath = false) {
    if (childPath) {
      return this.#HDPrivateKey.deriveChild(childPath).hdPublicKey.toString();
    }

    return this.#HDPrivateKey.hdPublicKey.toString();
  }

  set BAP_SERVER(bapServer) {
    this.#BAP_SERVER = bapServer;
    Object.keys(this.#ids).forEach((key) => {
      this.#ids[key].BAP_SERVER = bapServer;
    });
  }

  get BAP_SERVER() {
    return this.#BAP_SERVER;
  }

  set BAP_TOKEN(token) {
    this.#BAP_TOKEN = token;
    Object.keys(this.#ids).forEach((key) => {
      this.#ids[key].BAP_TOKEN = token;
    });
  }

  get BAP_TOKEN() {
    return this.#BAP_TOKEN;
  }

  /**
   * This function verifies that the given bapId matches the given root address
   * This is used as a data integrity check
   *
   * @param bapId BAP_ID instance
   */
  checkIdBelongs(bapId) {
    const derivedChild = this.#HDPrivateKey.deriveChild(bapId.rootPath);
    const checkRootAddress = derivedChild.publicKey.toAddress().toString();
    if (checkRootAddress !== bapId.rootAddress) {
      throw new Error('ID does not belong to this private key');
    }

    return true;
  }

  /**
   * Returns a list of all the identity keys that are stored in this instance
   *
   * @returns {string[]}
   */
  listIds() {
    return Object.keys(this.#ids);
  }

  /**
   * Create a new Id and link it to this BAP instance
   *
   * This function uses the length of the #ids of this class to determine the next valid path.
   * If not all ids related to this HDPrivateKey have been loaded, determine the path externally
   * and pass it to newId when creating a new ID.
   *
   * @param path
   * @param identityAttributes
   * @param idSeed
   * @returns {*}
   */
  newId(path = null, identityAttributes = {}, idSeed = '') {
    if (!path) {
      // get next usable path for this key
      path = this.getNextValidPath();
    }

    const newIdentity = new BAP_ID(this.#HDPrivateKey, identityAttributes, idSeed);
    newIdentity.BAP_SERVER = this.#BAP_SERVER;
    newIdentity.BAP_TOKEN = this.#BAP_TOKEN;

    newIdentity.rootPath = path;
    newIdentity.currentPath = Utils.getNextPath(path);

    const idKey = newIdentity.getIdentityKey();
    this.#ids[idKey] = newIdentity;
    this.#lastIdPath = path;

    return this.#ids[idKey];
  }

  /**
   * Remove identity
   *
   * @param idKey
   * @returns {*}
   */
  removeId(idKey) {
    delete this.#ids[idKey];
  }

  /**
   * Get the next valid path for the used HDPrivateKey and loaded #ids
   *
   * @returns {string}
   */
  getNextValidPath() {
    // prefer hardened paths
    if (this.#lastIdPath) {
      return Utils.getNextIdentityPath(this.#lastIdPath);
    }

    return `/0'/${Object.keys(this.#ids).length}'/0'`;
  }

  /**
   * Get a certain Id
   *
   * @param identityKey
   * @returns {null}
   */
  getId(identityKey) {
    return this.#ids[identityKey] || null;
  }

  /**
   * This function is used when manipulating ID's, adding or removing attributes etc
   * First create an id through this class and then use getId to get it. Then you can add/edit or
   * increment the signing path and then re-set it with this function.
   *
   * Note: when you getId() from this class, you will be working on the same object as this class
   * has and any changes made will be propagated to the id in this class. When you call exportIds
   * your new changes will also be included, without having to setId().
   *
   * @param bapId
   */
  setId(bapId) {
    if (bapId instanceof BAP_ID) {
      this.checkIdBelongs(bapId);

      this.#ids[bapId.getIdentityKey()] = bapId;
    } else {
      throw new Error('id is not an instance of BAP_ID');
    }
  }

  /**
   * This function is used to import IDs and attributes from some external storage
   *
   * The ID information should NOT be stored together with the HD private key !
   *
   * @param idData Array of ids that have been exported
   * @param encrypted Whether the data should be treated as being encrypted (default true)
   */
  importIds(idData, encrypted = true) {
    if (encrypted) {
      // we first need to decrypt the ids array using ECIES
      const ecies = ECIES();
      const derivedChild = this.#HDPrivateKey.deriveChild(ENCRYPTION_PATH);
      ecies.privateKey(derivedChild.privateKey);
      const decrypted = ecies.decrypt(
        Buffer.from(idData, Utils.isHex(idData) ? 'hex' : 'base64'),
      ).toString();
      idData = JSON.parse(decrypted);
    }

    let oldFormatImport = false;
    if (!idData.hasOwnProperty('ids')) {
      // old format id container
      oldFormatImport = true;
      idData = {
        lastIdPath: '',
        ids: idData,
      };
    }

    idData.ids.forEach((id) => {
      if (!id.identityKey || !id.identityAttributes || !id.rootAddress) {
        throw new Error('ID cannot be imported as it is not complete');
      }
      const importId = new BAP_ID(this.#HDPrivateKey, {}, id.idSeed);
      importId.BAP_SERVER = this.#BAP_SERVER;
      importId.BAP_TOKEN = this.#BAP_TOKEN;
      importId.import(id);

      this.checkIdBelongs(importId);

      this.#ids[importId.getIdentityKey()] = importId;

      if (oldFormatImport) {
        // overwrite with the last value on this array
        idData.lastIdPath = importId.currentPath;
      }
    });

    this.#lastIdPath = idData.lastIdPath;
  }

  /**
   * Export all the IDs of this instance for external storage
   *
   * By default this function will encrypt the data, using a derivative child of the main HD key
   *
   * @param encrypted Whether the data should be encrypted (default true)
   * @returns {[]|*}
   */
  exportIds(encrypted = true) {
    const idData = {
      lastIdPath: this.#lastIdPath,
      ids: [],
    };

    Object.keys(this.#ids)
      .forEach((key) => {
        idData.ids.push(this.#ids[key].export());
      });

    if (encrypted) {
      const ecies = ECIES();
      const derivedChild = this.#HDPrivateKey.deriveChild(ENCRYPTION_PATH);
      ecies.publicKey(derivedChild.publicKey);
      return ecies.encrypt(JSON.stringify(idData)).toString('base64');
    }

    return idData;
  }

  /**
   * Encrypt a string of data
   *
   * @param string
   * @returns {string}
   */
  encrypt(string) {
    const ecies = ECIES();
    const derivedChild = this.#HDPrivateKey.deriveChild(ENCRYPTION_PATH);
    ecies.publicKey(derivedChild.publicKey);
    return ecies.encrypt(string).toString('base64');
  }

  /**
   * Decrypt a string of data
   *
   * @param string
   * @returns {string}
   */
  decrypt(string) {
    const ecies = ECIES();
    const derivedChild = this.#HDPrivateKey.deriveChild(ENCRYPTION_PATH);
    ecies.privateKey(derivedChild.privateKey);
    return ecies.decrypt(Buffer.from(string, 'base64')).toString();
  }

  /**
   * Sign an attestation for a user
   *
   * @param attestationHash The computed attestation hash for the user - this should be calculated with the BAP_ID class for an identity for the user
   * @param identityKey The identity key we are using for the signing
   * @param counter
   * @param dataString Optional data string that will be appended to the BAP attestation
   * @returns {string[]}
   */
  signAttestationWithAIP(attestationHash, identityKey, counter = 0, dataString = '') {
    const id = this.getId(identityKey);
    if (!id || !(id instanceof BAP_ID)) {
      throw new Error('Could not find identity to attest with');
    }

    const attestationBuffer = this.getAttestationBuffer(attestationHash, counter, dataString);
    const { address, signature } = id.signMessage(attestationBuffer);

    return this.createAttestationTransaction(
      attestationHash,
      counter,
      address,
      signature,
      dataString,
    );
  }

  /**
   * Verify an AIP signed attestation for a user
   *
   * [
   *   '0x6a',
   *   '0x31424150537561506e66476e53424d33474c56397968785564596534764762644d54',
   *   '0x415454455354',
   *   '0x33656166366361396334313936356538353831366439336439643034333136393032376633396661623034386333633031333663343364663635376462383761',
   *   '0x30',
   *   '0x7c',
   *   '0x313550636948473232534e4c514a584d6f5355615756693757537163376843667661',
   *   '0x424954434f494e5f4543445341',
   *   '0x31477531796d52567a595557634638776f6f506a7a4a4c764d383550795a64655876',
   *   '0x20ef60c5555001ddb1039bb0f215e46571fcb39ee46f48b089d1c08b0304dbcb3366d8fdf8bafd82be24b5ac42dcd6a5e96c90705dd42e3ad918b1b47ac3ce6ac2'
   * ]
   *
   * @param tx Array of hex values for the OP_RETURN values
   * @returns {{}}
   */
  verifyAttestationWithAIP(tx) {
    if (
      !Array.isArray(tx)
      || tx[0] !== '0x6a'
      || tx[1] !== BAP_BITCOM_ADDRESS_HEX
    ) {
      throw new Error('Not a valid BAP transaction');
    }

    const dataOffset = tx[7] === '0x44415441' ? 5 : 0; // DATA
    const attestation = {
      type: Utils.hexDecode(tx[2]),
      hash: Utils.hexDecode(tx[3]),
      sequence: Utils.hexDecode(tx[4]),
      signingProtocol: Utils.hexDecode(tx[7 + dataOffset]),
      signingAddress: Utils.hexDecode(tx[8 + dataOffset]),
      signature: Utils.hexDecode(tx[9 + dataOffset], 'base64'),
    };

    if (dataOffset && tx[3] === tx[8]) {
      // valid data addition
      attestation.data = Utils.hexDecode(tx[9]);
    }

    try {
      const signatureBufferStatements = [];
      for (let i = 0; i < 6 + dataOffset; i++) {
        signatureBufferStatements.push(Buffer.from(tx[i].replace('0x', ''), 'hex'));
      }
      const attestationBuffer = Buffer.concat([
        ...signatureBufferStatements,
      ]);
      attestation.verified = this.verifySignature(
        attestationBuffer,
        attestation.signingAddress,
        attestation.signature,
      );
    } catch (e) {
      attestation.verified = false;
    }

    return attestation;
  }

  /**
   * For BAP attestations we use all fields for the attestation
   *
   * @param attestationHash
   * @param counter
   * @param address
   * @param signature
   * @param dataString Optional data string that will be appended to the BAP attestation
   * @returns {[string]}
   */
  createAttestationTransaction(attestationHash, counter, address, signature, dataString = '') {
    const transaction = ['0x6a', Utils.hexEncode(BAP_BITCOM_ADDRESS)];
    transaction.push(Utils.hexEncode('ATTEST'));
    transaction.push(Utils.hexEncode(attestationHash));
    transaction.push(Utils.hexEncode(`${counter}`));
    transaction.push('0x7c'); // |
    if (dataString && typeof dataString === 'string') {
      // data should be a string, either encrypted or stringified JSON if applicable
      transaction.push(Utils.hexEncode(BAP_BITCOM_ADDRESS));
      transaction.push(Utils.hexEncode('DATA'));
      transaction.push(Utils.hexEncode(attestationHash));
      transaction.push(Utils.hexEncode(dataString));
      transaction.push('0x7c'); // |
    }
    transaction.push(Utils.hexEncode(AIP_BITCOM_ADDRESS));
    transaction.push(Utils.hexEncode('BITCOIN_ECDSA'));
    transaction.push(Utils.hexEncode(address));
    transaction.push('0x' + Buffer.from(signature, 'base64').toString('hex'));

    return transaction;
  }

  /**
   * This is a re-creation of how the bitcoinfiles-sdk creates a hash to sign for AIP
   *
   * @param attestationHash
   * @param counter
   * @param dataString Optional data string
   * @returns {Buffer}
   */
  getAttestationBuffer(attestationHash, counter = 0, dataString = '') {
    // re-create how AIP creates the buffer to sign
    let dataStringBuffer = Buffer.from('');
    if (dataString) {
      dataStringBuffer = Buffer.concat([
        Buffer.from(BAP_BITCOM_ADDRESS),
        Buffer.from('DATA'),
        Buffer.from(attestationHash),
        Buffer.from(dataString),
        Buffer.from('7c', 'hex'),
      ]);
    }
    return Buffer.concat([
      Buffer.from('6a', 'hex'), // OP_RETURN
      Buffer.from(BAP_BITCOM_ADDRESS),
      Buffer.from('ATTEST'),
      Buffer.from(attestationHash),
      Buffer.from(`${counter}`),
      Buffer.from('7c', 'hex'),
      dataStringBuffer,
    ]);
  }

  /**
   * Verify that the identity challenge is signed by the address
   *
   * @param message Buffer or utf-8 string
   * @param address Bitcoin address of signee
   * @param signature Signature base64 string
   */
  verifySignature(message, address, signature) {
    // check the signature against the challenge
    const messageBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message);
    return Message.verify(
      messageBuffer,
      address,
      signature,
    );
  }

  /**
   * Check whether the given transaction (BAP OP_RETURN) is valid, is signed and that the
   * identity signing is also valid at the time of signing
   *
   * @param idKey
   * @param address
   * @param challenge
   * @param signature
   * @returns {Promise<boolean|*>}
   */
  async verifyChallengeSignature(idKey, address, challenge, signature) {
    // first we test locally before sending to server
    if (this.verifySignature(challenge, address, signature)) {
      const result = await this.getApiData('/attestation/valid', {
        idKey,
        challenge,
        signature,
      });
      return result.data;
    }

    return false;
  }

  /**
   * Check whether the given transaction (BAP OP_RETURN) is valid, is signed and that the
   * identity signing is also valid at the time of signing
   *
   * @param tx
   * @returns {Promise<boolean|*>}
   */
  async isValidAttestationTransaction(tx) {
    // first we test locally before sending to server
    if (this.verifyAttestationWithAIP(tx)) {
      return this.getApiData('/attestation/valid', {
        tx,
      });
    }

    return false;
  }

  /**
   * Get all signing keys for the given idKey
   *
   * @param address
   * @returns {Promise<*>}
   */
  async getIdentityFromAddress(address) {
    return this.getApiData('/identity/from-address', {
      address,
    });
  }

  /**
   * Get all signing keys for the given idKey
   *
   * @param idKey
   * @returns {Promise<*>}
   */
  async getIdentity(idKey) {
    return this.getApiData('/identity', {
      idKey,
    });
  }

  /**
   * Get all attestations for the given attestation hash
   *
   * @param attestationHash
   */
  async getAttestationsForHash(attestationHash) {
    // get all BAP ATTEST records for the given attestationHash
    return this.getApiData('/attestations', {
      hash: attestationHash,
    });
  }

  /**
   * Helper function to get attestation from a BAP API server
   *
   * @param apiUrl
   * @param apiData
   * @returns {Promise<any>}
   */
  async getApiData(apiUrl, apiData) {
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
};
