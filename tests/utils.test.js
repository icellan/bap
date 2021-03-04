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

  test('getNextPath', () => {
    expect(Utils.getNextPath('/0/0/1')).toBe('/0/0/2');
    expect(Utils.getNextPath('/0/2345/1')).toBe('/0/2345/2');
    expect(Utils.getNextPath('/0\'/2345\'/1\'')).toBe('/0\'/2345\'/2\'');
    expect(Utils.getNextPath('/5765/2345/2342')).toBe('/5765/2345/2343');
    expect(Utils.getNextPath('/5765\'/2345\'/2342\'')).toBe('/5765\'/2345\'/2343\'');
  });
});
