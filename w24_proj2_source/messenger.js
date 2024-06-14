'use strict'

const { generateKey, hkdf } = require('node:crypto')
/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

const { subtle } = require('node:crypto').webcrypto

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey  // use to sign and verify the signature
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   * Assume that the username is unique for each user, so it is enough to distinguish users
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    try {
      const certificate = {}
      // generate elgamal key pair
      this.EGKeyPair = await generateEG()
      // locate the public key in the certificate to send to other clients
      certificate.pub = this.EGKeyPair.pub
      certificate.username = username
      return certificate
    } catch (error) {
      console.error('Error generating certificate:', error)
      throw error
    }
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: ArrayBuffer
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    try {
      const certString = JSON.stringify(certificate)
      const verify = await verifyWithECDSA(this.caPublicKey, certString, signature)
      
      if (!verify) {
        throw new Error('Certificate verification failed')
      }

      this.certs[certificate.username] = certificate
      console.log(`get the valid certificate successfully from ${certificate.username}`)
    } catch (error) {
      console.error('Error receiving certificate:', error.message)
      throw error
    }
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, ArrayBuffer]
 */
  async sendMessage(name, plaintext) {

    if (!this.certs[name]) {
      throw new Error('Certificate not found');
    }

    const hmac_to_aes_key_messageKey = 'hmac_to_aes_key_messageKey'
    
    const header = {};

    if (!this.conns[name]) {
      this.conns[name] = {}
      this.conns[name].pub_current = null
      this.conns[name].pub_new = this.certs[name].pub
      // the first KeyChain (or the first RootKey)
      this.conns[name].keyChain= await subtle.generateKey({ name: 'HMAC', hash: 'SHA-384' }, true, ['sign'])
    }

    header.keyChain = this.conns[name].keyChain

    // check for the new receiving ratchet public key 
    if (this.conns[name].pub_new !== this.conns[name].pub_current) {
      const newEG_Key = await generateEG()
      this.conns[name].DH_key = await computeDH(newEG_Key.sec, this.conns[name].pub_new);
      const newKey = await HKDF(this.conns[name].DH_key, this.conns[name].keyChain, 'newKey');
      this.conns[name].keyChain = newKey[0]
      this.conns[name].sendingKeyRoot = newKey[1]
      this.conns[name].pub_current = this.conns[name].pub_new // update the pubKey
      this.conns[name].my_current_EG_Key = newEG_Key
    }

    // use hkdf to generate new key pair for sending message from the SendingKeyRoot
    const newSendingKeyPair = await HKDF(this.conns[name].DH_key, this.conns[name].sendingKeyRoot, 'newSendingKeyPair')

    this.conns[name].sendingKeyRoot = newSendingKeyPair[0]
    this.conns[name].messageKey = newSendingKeyPair[1] //encrypt the message with this key

    const ivGov = genRandomSalt(); //used as salt to derive the key to encrypt message
    const receiverIV = genRandomSalt(); //used to encrypt the message

    const messageKey1 = await HMACtoAESKey(this.conns[name].messageKey, hmac_to_aes_key_messageKey, true);
    const messageKey2 = await HMACtoAESKey(this.conns[name].messageKey, hmac_to_aes_key_messageKey, false)
    
    header.vGov = this.conns[name].my_current_EG_Key.pub  // the goverment use this to combine with their secKey to compute DH shared key
    header.ivGov = ivGov;
    header.receiverIV = receiverIV;

    // computeDH from self sec and govpub
    let govKey = await computeDH(this.conns[name].my_current_EG_Key.sec, this.govPublicKey)
    govKey = await HMACtoAESKey(govKey, govEncryptionDataStr)

    header.cGov = await encryptWithGCM(govKey, messageKey1, ivGov)  //the enc_messageKey
    const ciphertext = await encryptWithGCM(messageKey2, plaintext, receiverIV, JSON.stringify(header)); //encrypt the message that send to receiver

    return [header, ciphertext];
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
 *
 * Return Type: string
 */
  async receiveMessage(name, [header, ciphertext]) {
    if (!this.certs[name]) {
      throw new Error('Certificate not found');
    }
    process.stdout.write(`${name}: `);
    const hmac_to_aes_key_messageKey = 'hmac_to_aes_key_messageKey'

    // compute key for decrypting
    if (!this.conns[name]){
      this.conns[name] = {}
      this.conns[name].my_current_EG_Key = this.EGKeyPair
      this.conns[name].pub_current = null
      this.conns[name].pub_new = this.certs[name].pub
      }

    if (this.conns[name].pub_new !== header.vGov){
      this.conns[name].keyChain = header.keyChain
      this.conns[name].DH_key = await computeDH(this.conns[name].my_current_EG_Key.sec, header.vGov)      // prevent from eavesdroping
      const newKey = await HKDF(this.conns[name].DH_key, header.keyChain, 'newKey');
      this.conns[name].keyChain = newKey[0]
      this.conns[name].receivingKeyRoot = newKey[1]
      this.conns[name].pub_new = header.vGov
    }

    const newReceivingKeyPair = await HKDF(this.conns[name].DH_key, this.conns[name].receivingKeyRoot, 'newSendingKeyPair')// prevent from the replay attack, because the receivingKey is always generated each time
    this.conns[name].receivingKeyRoot = newReceivingKeyPair[0]
    this.conns[name].messageKey = newReceivingKeyPair[1]

    const messageKey = await HMACtoAESKey(this.conns[name].messageKey, hmac_to_aes_key_messageKey, false)
    let plaintext = await decryptWithGCM(messageKey, ciphertext, header.receiverIV, JSON.stringify(header))
    plaintext = bufferToString(plaintext)
    console.log(plaintext)
    return plaintext;
  }

}

module.exports = {
  MessengerClient
}
