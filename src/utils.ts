import bsv from 'bsv';
import {PathPrefix} from "./interface";

export const Utils = {
  /**
   * Helper function for encoding strings to hex
   *
   * @param string
   * @returns {string}
   */
  hexEncode(string: string) {
    return '0x' + Buffer.from(string).toString('hex');
  },

  /**
   * Helper function for encoding strings to hex
   *
   * @param hexString string
   * @param encoding BufferEncoding
   * @returns {string}
   */
  hexDecode(hexString: string, encoding: BufferEncoding = 'utf8') {
    return Buffer.from(hexString.replace('0x', ''), 'hex').toString(encoding);
  },

  /**
   * Helper function to generate a random nonce
   *
   * @returns {string}
   */
  getRandomString(length = 32) {
    return bsv.crypto.Random.getRandomBuffer(length).toString('hex');
  },

  /**
   * Test whether the given string is hex
   *
   * @param value any
   * @returns {boolean}
   */
  isHex(value: any) {
    if (typeof value !== 'string') {
      return false;
    }
    return /^[0-9a-fA-F]+$/.test(value);
  },

  /**
   * Get a signing path from a hex number
   *
   * @param hexString {string}
   * @param hardened {boolean} Whether to return a hardened path
   * @returns {string}
   */
  getSigningPathFromHex(hexString: string, hardened = true) {
    // "m/0/0/1"
    let signingPath = 'm';
    const signingHex = hexString.match(/.{1,8}/g);
    const maxNumber = 2147483648 - 1; // 0x80000000
    signingHex?.forEach((hexNumber) => {
      let number = Number('0x' + hexNumber);
      if (number > maxNumber) number -= maxNumber;
      signingPath += `/${number}${(hardened ? "'" : '')}`;
    });

    return signingPath;
  },

  /**
   * Increment that second to last part from the given part, set the last part to 0
   *
   * @param path string
   * @returns {*}
   */
  getNextIdentityPath(path: string): PathPrefix {
    const pathValues = path.split('/');
    const secondToLastPart = pathValues[pathValues.length - 2];

    let hardened = false;
    if (secondToLastPart.match('\'')) {
      hardened = true;
    }

    const nextPath = (Number(secondToLastPart.replace(/[^0-9]/g, '')) + 1).toString();
    pathValues[pathValues.length - 2] = nextPath + (hardened ? '\'' : '');
    pathValues[pathValues.length - 1] = '0' + (hardened ? '\'' : '');

    return pathValues.join('/') as PathPrefix;
  },

  /**
   * Increment that last part of the given path
   *
   * @param path string
   * @returns {*}
   */
  getNextPath(path: string) {
    const pathValues = path.split('/');
    const lastPart = pathValues[pathValues.length - 1];
    let hardened = false;
    if (lastPart.match('\'')) {
      hardened = true;
    }
    const nextPath = (Number(lastPart.replace(/[^0-9]/g, '')) + 1).toString();
    pathValues[pathValues.length - 1] = nextPath + (hardened ? '\'' : '');
    return pathValues.join('/');
  },
};
