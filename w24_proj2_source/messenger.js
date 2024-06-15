'use strict'

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
      throw new Error('Certificate not found')
    }

    const hmac_to_aes_key_messageKey = 'hmac_to_aes_key_messageKey'
    
    

    if (!this.conns[name]) {
      this.conns[name] = {}
      this.conns[name].pub_current = null
      this.conns[name].pub_new = this.certs[name].pub
      this.conns[name].keyChain= await computeDH(this.EGKeyPair.sec, this.certs[name].pub)
      this.conns[name].PN = 0
      this.conns[name].N = 0
    }


    if (this.conns[name].pub_new !== this.conns[name].pub_current) {
      const newEG_Key = await generateEG()
      this.conns[name].DH_key = await computeDH(newEG_Key.sec, this.conns[name].pub_new);
      const newKey = await HKDF(this.conns[name].DH_key, this.conns[name].keyChain, 'newKey');
      this.conns[name].keyChain = newKey[0]
      this.conns[name].sendingKeyRoot = newKey[1]
      this.conns[name].pub_current = this.conns[name].pub_new 
      this.conns[name].my_current_EG_Key = newEG_Key
      this.conns[name].PN = this.conns[name].N
      this.conns[name].N = 0
    }


    const newSendingKeyPair = await HKDF(this.conns[name].DH_key, this.conns[name].sendingKeyRoot, 'newSendingKeyPair')

    this.conns[name].sendingKeyRoot = newSendingKeyPair[0]
    this.conns[name].messageKey = newSendingKeyPair[1] 

    const ivGov = genRandomSalt()
    const receiverIV = genRandomSalt()

    const messageKey1 = await HMACtoAESKey(this.conns[name].messageKey, hmac_to_aes_key_messageKey, true);
    const messageKey2 = await HMACtoAESKey(this.conns[name].messageKey, hmac_to_aes_key_messageKey, false)
    
    const keyPairForGov = await generateEG()

    let govKey = await computeDH(keyPairForGov.sec, this.govPublicKey)
    govKey = await HMACtoAESKey(govKey, govEncryptionDataStr)

    const cGov = await encryptWithGCM(govKey, messageKey1, ivGov) 
    const NHeader = this.conns[name].N
    this.conns[name].N += 1
    const PNHeader = this.conns[name].PN


    const header = {
      pub: this.conns[name].my_current_EG_Key.pub,
      vGov: keyPairForGov.pub,
      ivGov: ivGov,
      receiverIV: receiverIV,
      cGov: cGov,
      N: NHeader,
      PN: PNHeader,
    }

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

    if (!this.conns[name]){
      this.conns[name] = {}
      this.conns[name].pub_current = null
      this.conns[name].pub_new = this.certs[name].pub
      this.conns[name].keyChain = await computeDH(this.EGKeyPair.sec, this.certs[name].pub)
      this.conns[name].currentReceivingChainLength = 0
      this.conns[name].numberSkippedMessagesInCurrentReceivingChain = 0
      this.conns[name].numberSkippedMessagesInNewReceivingChain = 0
      this.conns[name].skippedMessageKeys = {current:{},newReceive:{}} 
      this.conns[name].my_current_EG_Key = this.EGKeyPair
      this.conns[name].cnt = 0
    }
    // console.log(this.conns[name])

    if (this.conns[name].pub_new !== header.pub){
      this.conns[name].numberSkippedMessagesInCurrentReceivingChain = header.PN - this.conns[name].currentReceivingChainLength
      this.conns[name].numberSkippedMessagesInNewReceivingChain = header.N
      // console.log(this.conns[name].numberSkippedMessagesInCurrentReceivingChain, this.conns[name].numberSkippedMessagesInNewReceivingChain)
    }
      
    else {
      this.conns[name].numberSkippedMessagesInCurrentReceivingChain = header.N - this.conns[name].currentReceivingChainLength
    }

    this.conns[name].currentReceivingChainLength += 1


    if (this.conns[name].pub_new !== header.pub){

      if (this.conns[name].numberSkippedMessagesInCurrentReceivingChain !== 0){
        let receivingKey = this.conns[name].receivingKeyRoot
        for (let i = this.conns[name].currentReceivingChainLength; i < header.PN; i++ ){
          const newReceivingKeyPair = await HKDF(this.conns[name].DH_key, receivingKey, 'newSendingKeyPair')
          this.conns[name].skippedMessageKeys.current[i] = newReceivingKeyPair[1]
          receivingKey = newReceivingKeyPair[0]
        }

      }
      if (this.conns[name].numberSkippedMessagesInNewReceivingChain !== 0){

        this.conns[name].DH_key = await computeDH(this.conns[name].my_current_EG_Key.sec, header.pub)
        const newKey = await HKDF(this.conns[name].DH_key, this.conns[name].keyChain, 'newKey')
        this.conns[name].keyChain = newKey[0]
        this.conns[name].receivingKeyRoot = newKey[1]
        let receivingKey = this.conns[name].receivingKeyRoot
        for (let i = 0; i < header.N; i++){
          const newReceivingKeyPair = await HKDF(this.conns[name].DH_key, receivingKey, 'newSendingKeyPair')
          this.conns[name].skippedMessageKeys.newReceive[i] = newReceivingKeyPair[1]
          receivingKey = newReceivingKeyPair[0]
        }

      }


    }
    else if(this.conns[name].pub_new === header.pub && this.conns[name].numberSkippedMessagesInCurrentReceivingChain !== 0){

      let receivingKey = this.conns[name].receivingKeyRoot

      for (let i = this.conns[name].currentReceivingChainLength - 1; i < header.N; i++ ){
        const newReceivingKeyPair = await HKDF(this.conns[name].DH_key, receivingKey, 'newSendingKeyPair')
        this.conns[name].skippedMessageKeys.current[i] = newReceivingKeyPair[1]
        receivingKey = newReceivingKeyPair[0]
        }
      this.conns[name].receivingKeyRoot = receivingKey


    }

    console.log(this.conns[name].skippedMessageKeys)

    if (this.conns[name].pub_new !== header.pub){ 
      this.conns[name].DH_key = await computeDH(this.conns[name].my_current_EG_Key.sec, header.pub)
      const newKey = await HKDF(this.conns[name].DH_key, this.conns[name].keyChain, 'newKey')
      this.conns[name].keyChain = newKey[0]
      this.conns[name].receivingKeyRoot = newKey[1]
      this.conns[name].pub_new = header.pub

      this.conns[name].cnt = 0
    }

    if(header.N >= this.conns[name].cnt){
      let newReceivingKeyPair = await HKDF(this.conns[name].DH_key, this.conns[name].receivingKeyRoot, 'newSendingKeyPair')
 
      this.conns[name].receivingKeyRoot = newReceivingKeyPair[0]
   
      this.conns[name].messageKey = newReceivingKeyPair[1]
  
      // decrypt
      const messageKey = await HMACtoAESKey(this.conns[name].messageKey, hmac_to_aes_key_messageKey, false)

      let plaintext = await decryptWithGCM(messageKey, ciphertext, header.receiverIV, JSON.stringify(header))

      plaintext = bufferToString(plaintext)
  
      console.log(plaintext)
      this.conns[name].cnt += 1
      return plaintext
    }

    else {
      const messageKey = await HMACtoAESKey(this.conns[name].skippedMessageKeys.current[header.N], hmac_to_aes_key_messageKey, false)
      let plaintext = await decryptWithGCM(messageKey, ciphertext, header.receiverIV, JSON.stringify(header))
      plaintext = bufferToString(plaintext)
      console.log(plaintext)
      this.conns[name].cnt += 1
      return plaintext
    }
    


  }

}

module.exports = {
  MessengerClient
}
