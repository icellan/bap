export const BAP_BITCOM_ADDRESS = '1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT';
export const BAP_BITCOM_ADDRESS_HEX = '0x' + Buffer.from(BAP_BITCOM_ADDRESS).toString('hex');
export const AIP_BITCOM_ADDRESS = '15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva';
export const AIP_BITCOM_ADDRESS_HEX = '0x' + Buffer.from(AIP_BITCOM_ADDRESS).toString('hex');
export const BAP_SERVER = 'https://bap.network/api/v1';
export const MAX_INT = 2147483648 - 1; // 0x80000000

// This is just a choice for this library and could be anything else if so needed/wanted
// but it is advisable to use the same derivation between libraries for compatibility
export const SIGNING_PATH_PREFIX = 'm/424150\'/0\'/0\''; // BAP in hex
export const ENCRYPTION_PATH = `m/424150'/${MAX_INT}'/${MAX_INT}'`;
