/* eslint-disable no-unused-expressions */
const chai = require('chai')
const expect = chai.expect
const sinon = require('sinon')

chai.use(require('chai-passport-strategy'))

const Strategy = require('..')

describe('vodafone saml strategy', function () {
  var config = require('./saml.config.json')
  var strategy = new Strategy(config, function (profile, done) {
    if (profile) {
      return done(null, {id: profile.nameID}, {scope: 'read'})
    }
    return done(null, false)
  })
  var passport = chai.passport.use(strategy)

  describe('should redirect to the HTTP-Redirect in the config', function () {
    let error
    let redirectUrl
    let returnurl
    let SAMLRequest

    before((done) => {
      passport
        .error(e => {
          error = e
          done()
        })
        .redirect(url => {
          redirectUrl = url
          var matches = url.match(/https:\/\/accounts.google.com\/o\/saml2\/idp\?idpid=xxxxxxxxx&SAMLRequest=(.*)returnurl=(%2Fhome)$/)
          if (matches.length > 2) {
            SAMLRequest = matches[1]
            returnurl = matches[2]
          }
          done()
        })
        .req(req => {
          req.query = {
            returnurl: '/home'
          }
        })
        .authenticate({})
    })
    it('should not error before supplying redirect url', function () {
      expect(error).to.be.undefined
    })
    it('should supply redirect url with the return url', function () {
      expect(redirectUrl).to.match(/^https:\/\/accounts.google.com\/o\/saml2\/idp\?idpid=xxxxxxxxx&SAMLRequest=.*returnurl=%2Fhome$/)
      expect(returnurl).to.equal('%2Fhome')
      expect(SAMLRequest).to.be.a.string
    })
  })

  describe('should take a SAMLResponse', function (done) {
    let error
    let info
    let mockResponse = require('./saml.response')
    let fakeClock = sinon.useFakeTimers(Date.parse(mockResponse.mockDate))
    let redirectUrl
    let user

    before(done => {
      passport
        .error((e) => {
          error = e
          done()
        })
        .success((u, i) => {
          user = u
          info = i
          done()
        })
        .redirect((url) => {
          redirectUrl = url
          done()
        })
        .req((req) => {
          req.method = 'POST'
          req.url = '/auth'
          req.body = mockResponse.samlResponse
        })
        .authenticate({})
    })
    it('should not error when accepting saml response', () => {
      expect(error).to.be.undefined
    })
    it('should not redirect when accepting saml response', () => {
      expect(redirectUrl).to.be.undefined
    })
    it('should supply user', () => {
      expect(user).to.be.an('object')
      expect(user.id).to.equal('ben@subspacesw.com')
    })
    it('should supply info', () => {
      expect(info).to.be.an('object')
      expect(info.scope).to.equal('read')
    })
    after(() => {
      fakeClock.restore()
    })
  })
})
