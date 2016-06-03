/* eslint-env mocha */
'use strict'

const Code = require('code')
const expect = Code.expect
const nock = require('nock')
const Rbac = require('../lib/index')

describe('RBAC', function () {
  let checkPermission

  before(function () {
    checkPermission = function (user, permission) {
      return new Promise(function (resolve, reject) {
        const users = [
          {  // user 0
            'users:create': true,
            'users:remove': true
          },
          { // users 1
            'users:read': true
          }
        ]

        if (typeof permission === 'string') {
          permission = [permission]
        }

        const found = permission.some((p) => {
          return users[user] && users[user][p]
        })

        if (found) {
          return resolve()
        } else {
          return reject(new Error('Inexistent User or Permission'))
        }
      })
    }

    const opts = {
      reqheaders: {
        authorization: 'Bearer abcd'
      }
    }

    nock('http://www.example.com', opts)
      .post('/authorize', {
        permissions: ['users:create']
      })
      .times(1000)
      .reply(401)
      .post('/authorize', {
        permissions: ['users:read']
      })
      .times(1000)
      .reply(200, {
        id: 1000  // remote authorization can return claims about the principal
      })
      .log(console.log)
  })

  it('should Rbac throw if opts.checkPermission is not specified', function () {
    expect(() => new Rbac({ some: 'prop' })).to.throw(TypeError)
  })

  it('should Rbac throw if opts.remoteAuth is specified and opts.remoteAuth.url is not', function () {
    expect(() => new Rbac({ remoteAuth: {} })).to.throw(TypeError)
  })

  it('Rbac,authorize should throw if id not a Number or not convertible to a Number', function (done) {
    const rbac = new Rbac({ checkPermission: checkPermission })
    rbac
      .authorize('Not a Number', ['users:create'])
      .then(() => Code.fail('Rbac.authorize should fail'))
      .catch((err) => {
        expect(err).to.be.an.error('Invalid userId value: must be a number.')
        done()
      })
  })

  it('Rbac.authorize should throw if permissions is not an array', function (done) {
    const rbac = new Rbac({ checkPermission: checkPermission })
    rbac
      .authorize(1, 'users:create')
      .then(() => Code.fail('Rbac.authorize should fail'))
      .catch((err) => {
        expect(err).to.be.an.error('Invalid permissions value: must be a string or array.')
        done()
      })
  })

  it('Rbac.authorize should fail if user isn\'t allowed the existing permission', function (done) {
    const rbac = new Rbac({ checkPermission: checkPermission })
    rbac
      .authorize(1, ['users:create'])
      .then(() => Code.fail('Rbac.authorize should fail'))
      .catch((err) => {
        expect(err).to.be.an.error('Inexistent User or Permission')
        done()
      })
  })

  it('Rbac.authorize should pass if user is allowed the existing permission', function (done) {
    const rbac = new Rbac({ checkPermission: checkPermission })
    rbac
      .authorize(1, ['users:read'])
      .then(done)
      .catch(done)
  })

  it('Rbac.authorize should pass if user is allowed any of the existing permissions', function (done) {
    const rbac = new Rbac({ checkPermission: checkPermission })
    rbac
      .authorize(1, ['users:read', 'users:create'])
      .then(done)
      .catch(done)
  })

  it('Rbac.authorizeRemote should fail if user isn\'t allowed the existing permission', function (done) {
    const rbac = new Rbac({
      remoteAuth: {
        url: 'http://www.example.com/authorize',
        headers: {
          authorization: 'Bearer abcd'
        }
      }
    })
    rbac
      .authorizeRemote(['users:create'])
      .then(() => Code.fail('Rbac.authorize should fail'))
      .catch((err) => {
        expect(err.statusCode).to.equal(401)
        done()
      })
  })

  it('Rbac.authorizeRemote should pass if user is allowed the existing permission', function (done) {
    const rbac = new Rbac({
      remoteAuth: {
        url: 'http://www.example.com/authorize',
        headers: {
          authorization: 'Bearer abcd'
        }
      }
    })
    rbac
      .authorizeRemote(['users:read'])
      .then(() => done())
      .catch(done)
  })

  it('Rbac.express.authorizeRemote should fail if user isn\'t allowed the existing permission remotely', function (done) {
    const rbac = new Rbac({
      remoteAuth: {
        url: 'http://www.example.com/authorize'
      }
    })
    const middleware = rbac
      .express
      .authorizeRemote(['users:create'])

    const req = {
      headers: {
        authorization: 'Bearer abcd'
      }
    }

    middleware(req, null, (err) => {
      expect(err).to.be.an.error()
      expect(err.isBoom).to.exist().and.be.true()
      expect(err.output.statusCode).to.exist().and.equal(401)
      done()
    })
  })

  it('Rbac.express.authorizeRemote should pass if user is allowed the existing permission', function (done) {
    const rbac = new Rbac({
      remoteAuth: {
        url: 'http://www.example.com/authorize'
      }
    })
    const middleware = rbac
      .express
      .authorizeRemote(['users:read'])

    const req = {
      user: {
        some: 'prop'
      },
      headers: {
        authorization: 'Bearer abcd'
      }
    }

    middleware(req, null, (err) => {
      expect(err).to.be.undefined()
      expect(req.user.id).to.equal(1000) // Check claims returned by the remote authorization server
      expect(req.user.some).to.equal('prop')
      done()
    })
  })

  it('Rbac.express.authorize should fail if user isn\'t allowed the existing permission', function (done) {
    const rbac = new Rbac({ checkPermission: checkPermission })
    const middleware = rbac
      .express
      .authorize(['users:create'])

    const req = {
      user: {
        id: 1
      }
    }

    middleware(req, null, (err) => {
      expect(err).to.be.an.error()
      expect(err.isBoom).to.exist().and.be.true()
      expect(err.output.statusCode).to.exist().and.equal(401)
      done()
    })
  })

  it('Rbac.express.authorize should pass if user is allowed the existing permission', function (done) {
    const rbac = new Rbac({ checkPermission: checkPermission })
    const middleware = rbac
      .express
      .authorize(['users:read'])

    const req = {
      user: {
        id: 1
      }
    }

    middleware(req, null, (err) => {
      expect(err).to.be.undefined()
      done()
    })
  })

  it('Rbac.express.authorize should allow for userId being set', function (done) {
    const rbac = new Rbac({
      checkPermission: checkPermission,
      reqUserId: 'some.prop'
    })
    const middleware = rbac
      .express
      .authorize(['users:read'])

    const req = {
      some: {
        prop: 1
      }
    }

    middleware(req, null, (err) => {
      expect(err).to.be.undefined()
      done()
    })
  })
})
