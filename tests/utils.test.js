import {
  describe,
  expect,
  beforeEach,
  afterEach,
  test,
} from '@jest/globals';
import { Utils } from '../src/utils';

describe('random', () => {
  it('should generate random strings', () => {
    const randomString = Utils.getRandomString(32);
    expect(randomString.length).toEqual(64);

    const randomString2 = Utils.getRandomString(12);
    expect(randomString2.length).toEqual(24);
  });
});
