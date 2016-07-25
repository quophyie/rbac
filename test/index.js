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
          ['users:read'], // user 1
          ['users:eat', 'users:sleep', 'users:rave', 'users:repeat'] // user 2
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
      .post('/authorize', { permissions: ['users:create'] })
      .times(1000)
      .reply(401)

      .post('/authorize', { permissions: ['users:read'] })
      .times(1000)
      .reply(200, {
        id: 1000 // remote authorization can return claims about the principal
      })

      .post('/authorize', { permissions: ['users:read', 'users:void'] })
      .times(1000)
      .reply(200)

      .post('/authorize', { permissions: ['users:read:and', 'users:create:and'] })
      .times(1000)
      .reply(200)

      .post('/authorize')
      .times(1000)
      .reply(401)
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
  describe('- Rbac.authorize', () => {
    it('should throw if permissions is not an array', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize(1, { permissions: 'users:create', checkType: null })
        .then(() => Code.fail('Rbac.authorize should fail'))
        .catch((err) => {
          expect(err).to.be.an.error('Invalid permissions value: must be an array')
          done()
        })
    })

    it('should throw if permissions are more than one', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize(1, { permissions: ['users:read', 'users:create'], checkType: null })
        .then(() => Code.fail('Rbac.authorize should fail'))
        .catch((err) => {
          expect(err).to.be.an.error()
          expect(err.message).to.include('Invalid permissions:checkType combination.')
          done()
        })
    })

    it("should fail if user isn't allowed the existing permission", function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize(1, { permissions: ['users:create'], checkType: null })
        .then(() => Code.fail('Rbac.authorize should fail'))
        .catch((err) => {
          expect(err).to.be.an.error('Permission denied.')
          done()
        })
    })

    it('should pass if user is allowed the existing permission', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize(1, { permissions: ['users:read'], checkType: null })
        .then(() => done())
        .catch(done)
    })
  })
  // "authorize" method END

  // "authorize "OR" method START
  describe('- Rbac.authorize OR', () => {
    it('should fail if the number of permissions is less than 2', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize(1, { permissions: ['users:create'], checkType: 'OR' })
        .then(done)
        .catch((err) => {
          expect(err).to.be.an.error()
          expect(err.message).to.include('Invalid permissions:checkType combination.')
          done()
        })
    })

    it('should fail if the user has none of the permissions', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize(1, { permissions: ['users:milkyway', 'users:blackhole'], checkType: 'OR' })
        .then(done)
        .catch((err) => {
          expect(err).to.be.an.error('Permission denied.')
          done()
        })
    })

    it('should pass if the user has at least one permission', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize(1, { permissions: ['users:read', 'users:andromeda'], checkType: 'OR' })
        .then(() => done())
        .catch(done)
    })
  })
  // "authorize "OR" method END

  // "authorize "AND" method START
  describe('- Rbac.authorize AND', () => {
    it('should fail if the number of permissions is less than 2', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize(1, { permissions: ['users:create'], checkType: 'AND' })
        .then(done)
        .catch((err) => {
          expect(err).to.be.an.error()
          expect(err.message).to.include('Invalid permissions:checkType combination.')
          done()
        })
    })

    it.skip('should fail if the user has none of the permissions', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize(0, { permissions: ['users:milkyway', 'users:blackhole'], checkType: 'AND' })
        .then(done)
        .catch((err) => {
          expect(err).to.be.an.error('Permission denied.')
          done()
        })
    })

    it.skip('should fail if the user has just one of the permissions', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize(0, { permissions: ['users:create', 'users:blackhole'], checkType: 'AND' })
        .then(done)
        .catch((err) => {
          expect(err).to.be.an.error('Permission denied.')
          done()
        })
    })

    it.skip('should pass if the user has all permissions', function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      rbac
        .authorize(0, { permissions: ['users:create', 'users:remove'], checkType: 'AND' })
        .then(() => done())
        .catch(done)
    })
  })
  // "authorize "AND" method END

  // "Rbac.express.authorizeRemote" method START
  describe('- Rbac.express.authorizeRemote', () => {
    it("should fail if user isn't allowed the existing permission", function (done) {
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

    it("should fail if user isn't allowed the existing permission remotely", function (done) {
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
  })
  // "Rbac.express.authorizeRemote" method END

  // "Rbac.express.authorizeRemoteOr" method START
  describe('- Rbac.express.authorizeRemoteOr', () => {
    it("should fail if user isn't allowed the existing permission", function (done) {
      const rbac = new Rbac({
        remoteAuth: {
          url: 'http://www.example.com/authorize',
          headers: {
            authorization: 'Bearer abcd'
          }
        }
      })
      rbac
        .authorizeRemoteOr(['users:milkyway', 'users:blackhole'])
        .then(() => Code.fail('Rbac.authorize should fail'))
        .catch((err) => {
          expect(err.statusCode).to.equal(401)
          done()
        })
    })

    it('should pass if user is allowed at least one permission', function (done) {
      const rbac = new Rbac({
        remoteAuth: {
          url: 'http://www.example.com/authorize',
          headers: {
            authorization: 'Bearer abcd'
          }
        }
      })
      rbac
        .authorizeRemoteOr(['users:read', 'users:void'])
        .then(() => done())
        .catch(done)
    })

    it("should fail if user isn't allowed the existing permission remotely", function (done) {
      const rbac = new Rbac({
        remoteAuth: {
          url: 'http://www.example.com/authorize'
        }
      })
      const middleware = rbac
        .express
        .authorizeRemoteOr(['users:void', 'users:blank'])

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
  })
  // "Rbac.express.authorizeRemoteOr" method END

  // "Rbac.express.authorizeRemoteAnd" method START
  describe('- Rbac.express.authorizeRemoteAnd', () => {
    it("should fail if user isn't allowed the existing permission", function (done) {
      const rbac = new Rbac({
        remoteAuth: {
          url: 'http://www.example.com/authorize',
          headers: {
            authorization: 'Bearer abcd'
          }
        }
      })
      rbac
        .authorizeRemoteAnd(['users:milkyway', 'users:blackhole'])
        .then(() => Code.fail('Rbac.authorize should fail'))
        .catch((err) => {
          expect(err.statusCode).to.equal(401)
          done()
        })
    })

    it("should fail if user is doens't have all permissions", function (done) {
      const rbac = new Rbac({
        remoteAuth: {
          url: 'http://www.example.com/authorize',
          headers: {
            authorization: 'Bearer abcd'
          }
        }
      })
      rbac
        .authorizeRemoteAnd(['users:read', 'users:blackhole'])
        .then(() => Code.fail('Rbac.authorize should fail'))
        .catch((err) => {
          expect(err.statusCode).to.equal(401)
          done()
        })
    })

    it("should fail if user isn't allowed any of the permissions", function (done) {
      const rbac = new Rbac({
        remoteAuth: {
          url: 'http://www.example.com/authorize'
        }
      })
      const middleware = rbac
        .express
        .authorizeRemoteOr(['users:void', 'users:blank'])

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

    it('should pass if user is allowed all permissions', function (done) {
      const rbac = new Rbac({
        remoteAuth: {
          url: 'http://www.example.com/authorize',
          headers: {
            authorization: 'Bearer abcd'
          }
        }
      })
      rbac
        .authorizeRemoteOr(['users:read:and', 'users:create:and'])
        .then(() => done())
        .catch(done)
    })
  })
  // "Rbac.express.authorizeRemoteAnd" method END

  // "Rbac.express.authorize" method START
  describe('- Rbac.express.authorize', () => {
    it("should fail if user isn't allowed the existing permission", function (done) {
      const rbac = new Rbac({ getPermission: getPermission })
      const middleware = rbac
        .express
        .authorize('users:create')

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
        .authorize('users:read')

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
        .authorize('users:read')

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
