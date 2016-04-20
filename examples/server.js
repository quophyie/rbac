'use strict'

const AuthStrategy = require('@c8/auth')
const Express = require('express')
const bodyParser = require('body-parser')
const rbacExpress = require('./../lib/index').Express
const RolesDalFixture = require('./../test/lib/fixture/roles_interface_implementation')
const UsersDalFixture = require('./../test/lib/fixture/user_dal_interface_implementation')
let opts = {
  RolesDal: RolesDalFixture.RolesDalMockImplementation,
  UsersDal: UsersDalFixture.UsersDalMockImplementation
}

const server = new Express()

const users = {
  'john@doe.com': 'some_password'

}
const clients = {}

const auth = new AuthStrategy({
  secretOrKey: 'secret',
  verify: (jwtPayload, done) => {
    // Do some JWT checking here
    done(null, jwtPayload)  // This is passed onto `req.user`
  }
})

server.use(bodyParser.json())
server.use(auth.express.initialize())

server.post('/login', (req, res) => {
  let password = users[req.body.email]
  if (password !== req.body.password) {
    return res
      .status(401)
      .send({ error: 'Invalid credentials' })
  }
  let token = auth.issueToken({ email: req.body.email, id: 1 })
  res.send({ token: token })
})

server.post('/credentials', (req, res) => {
  let credentials = AuthStrategy.ApiKey.generate()
  clients[credentials.apiId] = credentials.apiKey
  res.send(credentials)
})

server.post('/token', (req, res) => {
  if (!clients[req.body.apiId] || req.body.apiKey !== clients[req.body.apiId]) {
    return res
      .status(401)
      .send({ error: 'Invalid credentials' })
  }
  let token = auth.issueTokenForApiKey(req.body, { apiId: req.body.apiId })
  res.send({ token: token })
})
server.get('/some-auth-route', auth.express.authenticate(), (req, res) => {
  res.send({ response: 'some secret content' })
})

server.get('/some-rbac', auth.express.authenticate(), rbacExpress.allow(['update']), (req, res) => {
  res.send({ response: 'some authorized content' })
})

server.get('/some-unauthorized-rbac', auth.express.authenticate(), rbacExpress.allow(['some_unkown_permision']), (req, res) => {
  res.send({ response: 'some other unknwn authorized content' })
})
server.use(rbacExpress.initialize(opts))
server.get('/some-unreachable', auth.express.authenticate(), (req, res) => {
  res.send({ response: 'this url should be unreachable as there are no permissions set on the route' })
})
server.listen(9000, () => {
  console.log('Listening on http://localhost:9000')
})
