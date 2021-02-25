import {
  describe,
  expect,
  beforeEach,
  afterEach,
  test,
} from '@jest/globals';
import { BAP } from '../src';

import testVectors from './data/test-vectors.json';

describe('test-vectors', () => {
  it('regression', () => {
    testVectors.forEach((v) => {
      const bap = new BAP(v.HDPrivateKey);
      const id = bap.newId();
      expect(id.getIdentityKey()).toBe(v.idKey);
      expect(id.rootPath).toBe(v.rootPath);
      expect(id.rootAddress).toBe(v.rootAddress);
      const tx = id.getInitialIdTransaction();
      expect(typeof tx[8]).toBe('string')
      expect(typeof v.tx[8]).toBe('string')
      delete tx[8]; // remove the signature, will be different
      delete v.tx[8]; // remove the signature, will be different
      expect(tx).toStrictEqual(v.tx);
    });
  });
});
