'/* eslint-env mocha */'
'use strict'
const Code = require('code')
const expect = Code.expect
const RbacExpress = require('./../../../../lib/index').Express
const RolesDalFixture = require('./../../fixture/roles_interface_implementation')
const createServer = require('./../../../mock_server')
const supertest = require('supertest')
const AuthStrategy = require('@c8/auth')
let server

let Auth = new AuthStrategy({
  secretOrKey: 'secret',
  verify: (jwtPayload, done) => {
    done(null, jwtPayload)
  }
})
let PORT = 0
PORT
describe('Rbac Express Tests', () => {
  describe('RbacExpress Creation', () => {
    it('Should throw TypeError with reference to RolesDal if roles DAL is not provided', (done) => {
      const constructor = () => {
        let rbacEx = RbacExpress.initialize({})
        rbacEx
      }
      expect(constructor).to.throw(TypeError, 'Parameter "rolesDalImpl" must be of Type "RolesDal"')
      done()
    })

  /* it('Should throw TypeError with reference to UsersDal if users DAL is not provided', (done) => {
    const constructor = () => {
      let opts = {
        RolesDal: RolesDalFixture.RolesDalMockImplementation
      }
      let rbacEx = RbacExpress.initialize(opts)
      rbacEx
    }
    expect(constructor).to.throw(TypeError, 'Parameter "usersDalImpl" must be of Type "UsersDal"')
    done()
  }) */
  })

  describe('RbacExpress Initialization Errors', () => {
    let bearerAndToken = ''
    const _RbacExpress = require('./../../../../lib/index').Express
    beforeEach(function (done) {
      server = createServer()

      const listener = server.listen(0)
      listener.on('listening', function () {
        PORT = listener.address().port
      })
      bearerAndToken = ''
      Auth.issueToken({id: 1}, null, (token) => {
        bearerAndToken += 'Bearer ' + token
        done()
      })
      server.use(Auth.express.initialize())
      server.use(Auth.express.authenticate())
    })
    it('Should return 500 with  Error "RbacExpress has not been initialised. Did you forget to call method "RbacExpress.express"" ', (done) => {
      server.get('/some-authenticated-route', _RbacExpress.allow(['update']), function (req, res) {
        res.send()
      })
      supertest(server)
        .get('/some-authenticated-route')
        .set('authorization', bearerAndToken)
        .expect(500).end((err, result) => {
          if (err) {
            return
          }
          done()
        })
    // .end(done)
    })
  })
  describe('RbacExpress Functionality Tests', () => {
    let opts = {
      RolesDal: RolesDalFixture.RolesDalMockImplementation // ,
    // UsersDal: UsersDalFixture.UsersDalMockImplementation
    }
    let rbacExpress
    let bearerAndToken = ''
    beforeEach(function (done) {
      server = createServer()
      bearerAndToken = ''
      Auth.issueToken({id: 1}, null, (token) => {
        bearerAndToken += 'Bearer ' + token

        done()
      })
      server.use(Auth.express.initialize())
      server.use(Auth.express.authenticate())
      server.get('/test', (req, res) => {
      })
      rbacExpress = RbacExpress.initialize(opts, server)
      server.use(rbacExpress)
    })

    it('Should permit users with the correct permissions', (done) => {
      server.get('/some-authenticated-route', RbacExpress.allow(['update']), function (req, res) {
        res.send()
      })
      supertest(server)
        .get('/some-authenticated-route')
        .set('authorization', bearerAndToken)
        .expect(200)
        .end(done)
    })
    /* it('Should perform remote authorisation and allow users with the permmssions that are not in the deny', (done) => {
      server.post('/some-remote-authenticated-route', RbacExpress.allow(['update'], { useRemoteAuthorization: true, remoteAuthorizationEndPoint: `localhost:${PORT}/authorize` }), function (req, res) {
        res.send()
      })

      // Verifies Rbac requests from remote clients
      server.post('/authorize', RbacExpress.verify())

      supertest(server)
        .post('/some-remote-authenticated-route')
        .set('authorization', bearerAndToken)
        .expect(200)
        .end(done)
    }) */

    it('Should NOT permit users with the incorrect correct permissions', (done) => {
      server.get('/some-authenticated-route', RbacExpress.allow(['some_unkown_permisson']), function (req, res) {
        res.send()
      })
      supertest(server)
        .get('/some-authenticated-route')
        .set('authorization', bearerAndToken)
        .expect(403)
        .end(done)
    })

    it('Should deny users with the provided permissions', (done) => {
      server.get('/some-authenticated-route', RbacExpress.deny(['update']), function (req, res) {
        res.send()
      })
      supertest(server)
        .get('/some-authenticated-route')
        .set('authorization', bearerAndToken)
        .expect(403)
        .end(done)
    })

    it('Should allow users with the permmssions that are not in the deny', (done) => {
      server.get('/some-authenticated-route', RbacExpress.deny(['some_non_deny_permisson']), function (req, res) {
        res.send()
      })
      supertest(server)
        .get('/some-authenticated-route')
        .set('authorization', bearerAndToken)
        .expect(200)
        .end(done)
    })

    it('Should deny users if permission is not specified', (done) => {
      server.get('/some-authenticated-route', function (req, res, next) {
        res.end()
      })
      supertest(server)
        .get('/some-authenticated-route')
        .set('authorization', bearerAndToken)
        .expect(403)
        .end(done)
    })
  })
})
