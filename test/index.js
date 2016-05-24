/* eslint-env mocha */
'use strict'

const Code = require('code')
const expect = Code.expect
const nock = require('nock')
const Rbac = require('../lib/index')

describe('RBAC', function () {
  let checkPermission

  before(function () {
    checkPermission = function (id, permissions) {
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

        const found = permissions.some((permission) => {
          return users[id] && users[id][permission]
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
        id: 1,
        permissions: ['users:create']
      })
      .times(1000)
      .reply(401)
      .post('/authorize', {
        id: 1,
        permissions: ['users:read']
      })
      .times(1000)
      .reply(200)
      .log(console.log)
  })

  it('should Rbac throw if opts.principals is not specified', function () {
    expect(() => new Rbac({
      some: 'prop'
    })).to.throw(TypeError)
  })

  it('should Rbac throw if checkPermission is not specified', function () {
    expect(() => new Rbac({
      principals: {
        users: {
          some: 'prop'
        }
      }
    })).to.throw(TypeError)
  })

  it('should Rbac throw if remoteAuth is specified and remoteAuth.url is not', function () {
    expect(() => new Rbac({
      principals: {
        users: {
          remoteAuth: {}
        }
      }
    })).to.throw(TypeError)
  })

  it('should Rbac throw if userId not a Number or not convertible to a Number', function (done) {
    const rbac = new Rbac({
      principals: {
        users: {
          checkPermission: checkPermission
        }
      }
    })

    rbac
      .authorize('Not a Number', 'users', ['users:create'])
      .then(() => Code.fail('Rbac.authorize should fail'))
      .catch((err) => {
        expect(err).to.be.an.error('Invalid id value: must be a number')
        done()
      })
  })

  it('Rbac.authorize should fail if user isn\'t allowed the existing permission locally', function (done) {
    const rbac = new Rbac({
      principals: {
        users: {
          checkPermission: checkPermission
        }
      }
    })

    rbac
      .authorize(1, 'users', ['users:create'])
      .then(() => Code.fail('Rbac.authorize should fail'))
      .catch((err) => {
        expect(err).to.be.an.error('Inexistent User or Permission')
        done()
      })
  })

  it('Rbac.authorize should fail if user isn\'t of the configured type locally', function (done) {
    const rbac = new Rbac({
      principals: {
        users: {
          checkPermission: checkPermission
        }
      }
    })

    rbac
      .authorize(1, 'apps', ['users:create'])
      .then(() => Code.fail('Rbac.authorize should fail'))
      .catch((err) => {
        expect(err).to.be.an.error('Principal type does not exist')
        done()
      })
  })

  it('Rbac.authorize should pass if user is allowed the existing permission locally', function (done) {
    const rbac = new Rbac({
      principals: {
        users: {
          checkPermission: checkPermission
        }
      }
    })

    rbac
      .authorize(1, 'users', ['users:read'])
      .then(done)
      .catch(done)
  })

  it('Rbac.authorize should pass if user is allowed any of the existing permissions locally', function (done) {
    const rbac = new Rbac({
      principals: {
        users: {
          checkPermission: checkPermission
        }
      }
    })

    rbac
      .authorize(1, 'users', ['users:read', 'users:create'])
      .then(done)
      .catch(done)
  })

  it('Rbac.authorize should fail if user isn\'t allowed the existing permission remotely', function (done) {
    const rbac = new Rbac({
      principals: {
        users: {
          remoteAuth: {
            url: 'http://www.example.com/authorize',
            headers: {
              authorization: 'Bearer abcd'
            }
          }
        }
      }
    })
    rbac
      .authorize(1, 'users', ['users:create'])
      .then(() => Code.fail('Rbac.authorize should fail'))
      .catch((err) => {
        expect(err.statusCode).to.equal(401)
        done()
      })
  })

  it('Rbac.authorize should pass if user is allowed the existing permission remotely', function (done) {
    const rbac = new Rbac({
      principals: {
        users: {
          remoteAuth: {
            url: 'http://www.example.com/authorize',
            headers: {
              authorization: 'Bearer abcd'
            }
          }
        }
      }
    })
    rbac
      .authorize(1, 'users', ['users:read'])
      .then(done)
      .catch(done)
  })

  it('Rbac.express.authorize should fail if user isn\'t allowed the existing permission remotely', function (done) {
    const rbac = new Rbac({
      principals: {
        users: {
          remoteAuth: {
            url: 'http://www.example.com/authorize'
          }
        }
      }
    })
    const middleware = rbac
      .express
      .authorize(['users:create'])

    const req = {
      user: {
        id: 1,
        type: 'users'
      },
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
      principals: {
        users: {
          remoteAuth: {
            url: 'http://www.example.com/authorize'
          }
        }
      }
    })
    const middleware = rbac
      .express
      .authorize(['users:read'])

    const req = {
      user: {
        id: 1,
        type: 'users'
      },
      headers: {
        authorization: 'Bearer abcd'
      }
    }

    middleware(req, null, (err) => {
      expect(err).to.be.undefined()
      done()
    })
  })

  it('Rbac.express.authorize should fail if user isn\'t allowed the existing permission locally', function (done) {
    const rbac = new Rbac({
      principals: {
        users: {
          checkPermission: checkPermission
        }
      }
    })
    const middleware = rbac
      .express
      .authorize(['users:create'])

    const req = {
      user: {
        id: 1,
        type: 'users'
      },
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
    const rbac = new Rbac({
      principals: {
        users: {
          checkPermission: checkPermission
        }
      }
    })
    const middleware = rbac
      .express
      .authorize(['users:read'])

    const req = {
      user: {
        id: 1,
        type: 'users'
      },
      headers: {
        authorization: 'Bearer abcd'
      }
    }

    middleware(req, null, (err) => {
      expect(err).to.be.undefined()
      done()
    })
  })

  it('Rbac.express.authorize should allow for userId being set', function (done) {
    const rbac = new Rbac({
      principals: {
        users: {
          checkPermission: checkPermission
        }
      },
      getReqId: (req) => req.some.prop,
      getReqType: (req) => req.some.type
    })
    const middleware = rbac
      .express
      .authorize(['users:read'])

    const req = {
      some: {
        prop: 1,
        type: 'users'
      },
      headers: {
        authorization: 'Bearer abcd'
      }
    }

    middleware(req, null, (err) => {
      expect(err).to.be.undefined()
      done()
    })
  })
})
