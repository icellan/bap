import bsv from 'bsv';

export const BAP_POA = class {
  #HDPrivateKey: bsv.HDPrivateKey;

  constructor(HDPrivateKey: bsv.HDPrivateKey) {
    this.#HDPrivateKey = HDPrivateKey;
  }
};
