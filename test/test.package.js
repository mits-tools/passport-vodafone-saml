const chai = require('chai')
const expect = chai.expect
var strategy = require('..')

describe('passport-vodafone-saml', function () {
  it('should export Strategy constructor', function () {
    expect(strategy.Strategy).to.be.a('function')
  })

  it('should export Strategy constructor as module', function () {
    expect(strategy).to.be.a('function')
    expect(strategy).to.equal(strategy.Strategy)
  })
})
