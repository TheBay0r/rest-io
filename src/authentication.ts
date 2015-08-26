module authentication {
  var CryptoJS = require('crypto-js');
  var HMAC = require('crypto-js/hmac-sha256');
  var AES = require('crypto-js/aes');

  export function encryptPassword(password: string) {
    return HMAC(password, process.env.REST_IO_HMAC_KEY).toString();
  }

  // add user role to auth creation
  export function createAuthToken(userId: string) {
    var authToken = AES.encrypt(`${userId};${new Date().getTime()}`, process.env.REST_IO_AES_KEY);
    return authToken.toString();
  }

  // add user role to be decrypted and broken down to separate messages
  export function decryptAuthToken(authToken: string) {
    var decryptedMessage = AES.decrypt(authToken, process.env.REST_IO_AES_KEY);
    var brokenMessage = decryptedMessage.toString(CryptoJS.enc.Utf8).split(';');
    if (brokenMessage.length !== 2) {
      throw new Error('corrupt auth token');
    }
    return {
      id: brokenMessage[0],
      createdAt: new Date(parseInt(brokenMessage[1], 10))
    };
  }
}

export = authentication;
