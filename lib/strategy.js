'use strict';

const metadata = require('./metadata');
const crypto = require('crypto');
const debug = require('debug')('passport-vodafone-saml');
const fs = require('fs');
const SamlStrategy = require('passport-saml').Strategy;
const path = require('path');
const util = require('util');
const DOMParser = require('xmldom').DOMParser;
const select = require('xpath.js');

function Strategy(options, verify) {
  const idpMetadata = metadata.parseIdpFile(path.resolve(options.metadataFile));
  options.entryPoint = idpMetadata.redirectLocation;
  options.cert = idpMetadata.cert;
  options.callbackUrl = `${options.sp.entityId}saml/login/${options.name}`;
  options.issuer = options.sp.entityId;
  options.identifierFormat = options.sp.nameIdFormat;
  options.logoutCallbackUrl = `${options.sp.entityId}saml/logout/${options.name}`; 

  debug('Stategy options %j', options);
  SamlStrategy.call(this, options, verify);

  this.name = options.name;
  this._authenticate = this.authenticate;
  this._getAdditionalParams = this._saml.getAdditionalParams;
  this._saml.getAdditionalParams = (req, options) => {
    const params = this._getAdditionalParams.call(this._saml, req, options);
    params.returnurl = req.query.returnurl;
    return params;
  };
}

util.inherits(Strategy, SamlStrategy);

module.exports = Strategy;
