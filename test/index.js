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
        return Promise.resolve()
      } else {
        return Promise.reject(new Error('Inexistent User or Permission'))
      }
    }

    const opts = {
      reqheaders: {
        authorization: 'Bearer abcd'
      }
    }

    nock('http://www.example.com', opts)
      .post('/authorize', {
        userId: 1,
        permission: 'users:create'
      })
      .reply(401)
      .post('/authorize', {
        userId: 1,
        permission: 'users:read'
      })
      .reply(200)
      .post('/authorize', {
        userId: 1,
        permission: 'users:create'
      })
      .reply(401)
      .post('/authorize', {
        userId: 1,
        permission: 'users:read'
      })
      .reply(200)
  })

  it('should Rbac throw if opts.checkPermission is not specified', function () {
    expect(() => new Rbac({ some: 'prop' })).to.throw(TypeError)
  })

  it('should Rbac throw if opts.remoteAuth is specified and opts.remoteAuth.url is not', function () {
    expect(() => new Rbac({ remoteAuth: {} })).to.throw(TypeError)
  })

  it('Rbac.authorize should fail if user isn\'t allowed the existing permission locally', function (done) {
    const rbac = new Rbac({ checkPermission: checkPermission })
    rbac
      .authorize(1, 'users:create')
      .then(() => Code.fail('Rbac.authorize should fail'))
      .catch((err) => {
        expect(err).to.be.an.error('Inexistent User or Permission')
        done()
      })
  })

  it('Rbac.authorize should pass if user is allowed the existing permission locally', function (done) {
    const rbac = new Rbac({ checkPermission: checkPermission })
    rbac
      .authorize(1, 'users:read')
      .then(done)
      .catch(done)
  })

  it('Rbac.authorize should pass if user is allowed any of the existing permissions locally', function (done) {
    const rbac = new Rbac({ checkPermission: checkPermission })
    rbac
      .authorize(1, ['users:read', 'users:create'])
      .then(done)
      .catch(done)
  })

  it('Rbac.authorize should fail if user isn\'t allowed the existing permission remotely', function (done) {
    const rbac = new Rbac({
      remoteAuth: {
        url: 'http://www.example.com/authorize',
        headers: {
          authorization: 'Bearer abcd'
        }
      }
    })
    rbac
      .authorize(1, 'users:create')
      .then(() => Code.fail('Rbac.authorize should fail'))
      .catch((err) => {
        expect(err.statusCode).to.equal(401)
        done()
      })
  })

  it('Rbac.authorize should pass if user is allowed the existing permission remotely', function (done) {
    const rbac = new Rbac({
      remoteAuth: {
        url: 'http://www.example.com/authorize',
        headers: {
          authorization: 'Bearer abcd'
        }
      }
    })
    rbac
      .authorize(1, 'users:read')
      .then(done)
      .catch(done)
  })

  it('Rbac.express.authorize should fail if user isn\'t allowed the existing permission remotely', function (done) {
    const rbac = new Rbac({
      remoteAuth: {
        url: 'http://www.example.com/authorize'
      }
    })
    const middleware = rbac
      .express
      .authorize('users:create')

    const req = {
      user: { id: 1 },
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

  it('Rbac.express.authorize should pass if user is allowed the existing permission remotely', function (done) {
    const rbac = new Rbac({
      remoteAuth: {
        url: 'http://www.example.com/authorize'
      }
    })
    const middleware = rbac
      .express
      .authorize('users:read')

    const req = {
      user: { id: 1 },
      headers: {
        authorization: 'Bearer abcd'
      }
    }

    middleware(req, null, (err) => {
      expect(err).to.be.undefined()
      expect(req.rbac).to.exist().and.be.an.object()
      expect(req.rbac.permission).to.exist()
      done()
    })
  })

  it('Rbac.express.authorize should fail if user isn\'t allowed the existing permission locally', function (done) {
    const rbac = new Rbac({ checkPermission: checkPermission })
    const middleware = rbac
      .express
      .authorize('users:create')

    const req = {
      user: { id: 1 },
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

  it('Rbac.express.authorize should pass if user is allowed the existing permission locally', function (done) {
    const rbac = new Rbac({ checkPermission: checkPermission })
    const middleware = rbac
      .express
      .authorize('users:read')

    const req = {
      user: { id: 1 },
      headers: {
        authorization: 'Bearer abcd'
      }
    }

    middleware(req, null, (err) => {
      expect(err).to.be.undefined()
      expect(req.rbac).to.exist().and.be.an.object()
      expect(req.rbac.permission).to.exist()
      done()
    })
  })
})
