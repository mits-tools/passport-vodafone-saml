'use strict'

var forge = require('node-forge'),
  pki = forge.pki

function x509KeyInfo (certificatePEM) {
  if (!(this instanceof x509KeyInfo)) {
    return new x509KeyInfo()
  }

  if (Buffer.isBuffer(certificatePEM)) {
    certificatePEM = certificatePEM.toString('ascii')
  }

  if (certificatePEM == null || typeof certificatePEM !== 'string') {
    throw new Error('certificatePEM must be a valid certificate in PEM format')
  }

  this._certificatePEM = certificatePEM

  this.getKeyInfo = function (key, prefix) {
    var keyInfoXml,
      certObj,
      certBodyInB64

    prefix = prefix || ''
    prefix = prefix ? prefix + ':' : prefix

    certBodyInB64 = forge.util.encode64(forge.pem.decode(this._certificatePEM)[0].body)
    certObj = pki.certificateFromPem(this._certificatePEM)

    keyInfoXml = '<' + prefix + 'X509Data>'

    keyInfoXml += '<' + prefix + 'X509Certificate>'
    keyInfoXml += certBodyInB64
    keyInfoXml += '</' + prefix + 'X509Certificate>'

    keyInfoXml += '</' + prefix + 'X509Data>'

    return keyInfoXml
  }

  this.getKey = function () {
    return this._certificatePEM
  }
}

function getSubjectName (certObj) {
  var subjectFields,
    fields = ['CN', 'OU', 'O', 'L', 'ST', 'C']

  if (certObj.subject) {
    subjectFields = fields.reduce(function (subjects, fieldName) {
      var certAttr = certObj.subject.getField(fieldName)

      if (certAttr) {
        subjects.push(fieldName + '=' + certAttr.value)
      }

      return subjects
    }, [])
  }

  return Array.isArray(subjectFields) ? subjectFields.join(',') : ''
}

module.exports = x509KeyInfo
