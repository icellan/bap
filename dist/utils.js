"use strict";var _interopRequireDefault=require("@babel/runtime/helpers/interopRequireDefault");Object.defineProperty(exports,"__esModule",{value:!0}),exports.Utils=void 0;var _bsv=_interopRequireDefault(require("bsv")),Utils={hexEncode:function hexEncode(a){return"0x"+Buffer.from(a).toString("hex")},hexDecode:function hexDecode(a){var b=1<arguments.length&&arguments[1]!==void 0?arguments[1]:"utf8";return Buffer.from(a.replace("0x",""),"hex").toString(b)},getRandomString:function getRandomString(){var a=0<arguments.length&&arguments[0]!==void 0?arguments[0]:32;return _bsv["default"].crypto.Random.getRandomBuffer(a).toString("hex")},isHex:function isHex(a){return!("string"!=typeof a)&&/^[0-9a-fA-F]+$/.test(a)},getSigningPathFromHex:function getSigningPathFromHex(a){var b=!(1<arguments.length&&void 0!==arguments[1])||arguments[1],c="m",d=a.match(/.{1,8}/g),e=2147483647;return d.forEach(function(a){var d=+("0x"+a);d>e&&(d-=e),c+="/".concat(d).concat(b?"'":"")}),c}};exports.Utils=Utils;