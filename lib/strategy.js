'use strict';

const metadata = require('./metadata');
const crypto = require('crypto');
const fs = require('fs');
const saml = require('passport-saml');
const path = require('path');
const select = require('xpath.js');
const DOMParser = require('xmldom').DOMParser;

const SamlStrategy = require('passport-saml').Strategy;

function Strategy(options, verify) {
  const idpMetadata = metadata.parseIdpFile(path.resolve(options.metadataFile));
  options.entryPoint = idpMetadata.redirectLocation;
  options.cert = idpMetadata.cert;
  options.callbackUrl = `${options.sp.entityId}saml/login/${options.name}`;
  options.issuer = options.sp.entityId;
  options.identifierFormat = options.sp.nameIdFormat;
  options.logoutCallbackUrl = `${options.sp.entityId}saml/logout/${options.name}`; 
  this._verify = verify;

  SamlStrategy.call(this, options, this.verify);

  this.name = options.name;
  this._authenticate = this.authenticate;
  this._getAdditionalParams = this._saml.getAdditionalParams;
  this._saml.getAdditionalParams = function(req, options) {
    const params = this._getAdditionalParams.call(this._saml, req, options);
    params.returnurl = req.query.returnurl;
    return params;
  };
}

util.inherits(Strategy, SamlStrategy);
