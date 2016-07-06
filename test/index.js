/* eslint-env mocha */
'use strict'

const Code = require('code')
const expect = Code.expect
const nock = require('nock')
const Rbac = require('../lib/index')

describe('RBAC', function () {
  let getPermission

  before(function () {
    getPermission = function (id) {
      return new Promise((resolve, reject) => {
        const users = [
          ['users:create', 'users:remove'], // user 0
          ['users:read']  // user 1
        ]
        if (users[id]) {
          resolve(users[id])
        } else {
          reject(new Error('Inexistent User'))
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
  })

  describe('- UNIT Tests', () => {
    it('should Rbac throw if opts.getPermission is not specified', function () {
      expect(() => new Rbac({ some: 'prop' })).to.throw(TypeError)
    })

    it('should Rbac throw if opts.remoteAuth is specified and opts.remoteAuth.url is not', function () {
      expect(() => new Rbac({ remoteAuth: {} })).to.throw(TypeError)
    })
  })

  // "authorize" method START
  describe('- Rbac.authorize method', () => {
    it('should throw if id not a Number or not convertible to a Number', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize('Not a Number', ['users:create'])
        .then(() => Code.fail('Rbac.authorize should fail'))
        .catch((err) => {
          expect(err).to.be.an.error('Invalid userId value: must be a number.')
          done()
        })
    })

    it('should throw if permissions is not an array', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize(1, 'users:create')
        .then(() => Code.fail('Rbac.authorize should fail'))
        .catch((err) => {
          expect(err).to.be.an.error('Invalid permissions value: must be a string or array.')
          done()
        })
    })

    it('should fail if user isn\'t allowed the existing permission', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize(1, ['users:create'])
        .then(() => Code.fail('Rbac.authorize should fail'))
        .catch((err) => {
          expect(err).to.be.an.error('Permission denied.')
          done()
        })
    })

    it('should pass if user is allowed the existing permission', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize(1, ['users:read'])
        .then(() => done())
        .catch(done)
    })

    it('should pass if user is allowed any of the existing permissions', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize(1, ['users:read', 'users:create'])
        .then(() => done())
        .catch(done)
    })
  })
  // "authorize" method END

  // "Rbac.express.authorizeRemote" method START
  describe('- Rbac.express.authorizeRemote', () => {
    it('should fail if user isn\'t allowed the existing permission', function (done) {
      const rbac = new Rbac({
        remoteAuth: {
          url: 'http://www.example.com/authorize',
          headers: {
            authorization: 'Bearer abcd'
          }
        }
      })
      rbac
        .authorizeRemote('users:create')
        .then(() => Code.fail('Rbac.authorize should fail'))
        .catch((err) => {
          expect(err.statusCode).to.equal(401)
          done()
        })
    })

    it('should pass if user is allowed the existing permission', function (done) {
      const rbac = new Rbac({
        remoteAuth: {
          url: 'http://www.example.com/authorize',
          headers: {
            authorization: 'Bearer abcd'
          }
        }
      })
      rbac
        .authorizeRemote('users:read')
        .then(() => done())
        .catch(done)
    })

    it('should fail if user isn\'t allowed the existing permission remotely', function (done) {
      const rbac = new Rbac({
        remoteAuth: {
          url: 'http://www.example.com/authorize'
        }
      })
      const middleware = rbac
        .express
        .authorizeRemote('users:create')

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

    it('should pass if user is allowed the existing permission', function (done) {
      const rbac = new Rbac({
        remoteAuth: {
          url: 'http://www.example.com/authorize'
        }
      })
      const middleware = rbac
        .express
        .authorizeRemote('users:read')

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
  })
  // "Rbac.express.authorizeRemote" method END

  // "Rbac.express.authorize" method START
  describe('- Rbac.express.authorize', () => {
    it('should fail if user isn\'t allowed the existing permission', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
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

    it('should pass if user is allowed the existing permission', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
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

    it('should allow for userId being set', function (done) {
      const rbac = new Rbac({
        getPermission: getPermission,
        getReqId: (req) => req.some.prop
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
  // "Rbac.express.authorize" method END
})
