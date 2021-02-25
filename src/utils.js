import bsv from 'bsv';

export const Utils = {
  /**
   * Helper function for encoding strings to hex
   *
   * @param string
   * @returns {string}
   */
  hexEncode(string) {
    return '0x' + Buffer.from(string).toString('hex');
  },

  /**
   * Helper function for encoding strings to hex
   *
   * @param hexString
   * @param encoding
   * @returns {string}
   */
  hexDecode(hexString, encoding = 'utf8') {
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
   * @param value
   * @returns {boolean}
   */
  isHex(value) {
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
  getSigningPathFromHex(hexString, hardened = true) {
    // "m/0/0/1"
    let signingPath = 'm';
    const signingHex = hexString.match(/.{1,8}/g);
    const maxNumber = 2147483648 - 1; // 0x80000000
    signingHex.forEach((hexNumber) => {
      let number = Number('0x' + hexNumber);
      if (number > maxNumber) number -= maxNumber;
      signingPath += `/${number}${(hardened ? "'" : '')}`;
    });

    return signingPath;
  },
};
