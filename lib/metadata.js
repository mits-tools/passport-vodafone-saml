const X509KeyInfo = require('./x509KeyInfo')
const fs = require('fs')
const FileKeyInfo = require('xml-crypto').FileKeyInfo
const SignedXml = require('xml-crypto').SignedXml
const select = require('xml-crypto').xpath
const DOMParser = require('xmldom').DOMParser

const md = 'urn:oasis:names:tc:SAML:2.0:metadata'
const ds = 'http://www.w3.org/2000/09/xmldsig#'

const parseIdp = (metadataString) => {
  const doc = new DOMParser().parseFromString(metadataString)
  const idpDescriptor = doc.documentElement.getElementsByTagNameNS(md, 'IDPSSODescriptor')
  if (idpDescriptor.length !== 1) {
    throw new Error('unexpected idp descriptor, none or multiple idps defined')
  }
  const keyDescriptors = idpDescriptor.item(0).getElementsByTagNameNS(md, 'KeyDescriptor')
  let signingKey
  for (var index = 0; index < keyDescriptors.length; index++) {
    let keyDescriptor = keyDescriptors.item(index)
    if (keyDescriptor.getAttribute('use') === 'signing') {
      signingKey = keyDescriptor
        .getElementsByTagNameNS(ds, 'KeyInfo').item(0)
        .getElementsByTagNameNS(ds, 'X509Data').item(0)
        .getElementsByTagNameNS(ds, 'X509Certificate').item(0)
        .firstChild.nodeValue
    }
  }
  if (!signingKey) {
    throw new Error('no signing key in idp metadata, this is needed to validate saml assertions')
  }
  const signOnServices = idpDescriptor.item(0).getElementsByTagNameNS(md, 'SingleSignOnService')
  let redirectLocation
  for (index = 0; index < signOnServices.length; index++) {
    let service = signOnServices.item(index)
    if (service.getAttribute('Binding') === 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect') {
      redirectLocation = service.getAttribute('Location')
    }
  }
  return {
    entityId: doc.documentElement.getAttribute('entityID'),
    redirectLocation: redirectLocation,
    signingKey: signingKey
  }
}

const parseIdpFile = (filePath) => {
  const metadataString = fs.readFileSync(filePath, 'utf-8')
  return parseIdp(metadataString)
}

const sign = (xml, xpath, signingCert, signingKey) => {
  const sig = new SignedXml()
  sig.keyInfoProvider = new X509KeyInfo(signingCert)

  // this is how you do an enveloped signature
  sig.addReference(
    xpath,
    ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
    'http://www.w3.org/2000/09/xmldsig#sha1',
    '',
    '',
    '',
    false
  )
  sig.signingKey = signingKey
  sig.computeSignature(xml, {location: {reference: xpath, action: 'prepend'}, prefix: 'ds'})
  const signedXml = sig.getSignedXml()
  return signedXml
}

const verify = (xml, signingCert) => {
  const doc = new DOMParser().parseFromString(xml)
  const signature = select(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0]
  const sig = new SignedXml()
  sig.keyInfoProvider = new FileKeyInfo(signingCert)
  sig.loadSignature(signature)
  const res = sig.checkSignature(xml)
  return [res, sig.validationErrors]
}

module.exports.parseIdpFile = parseIdpFile
module.exports.sign = sign
module.exports.verify = verify

// if (require.main === module) {
//   console.log(module.exports[process.argv[2]].apply(null, process.argv.slice(3)));
// }
