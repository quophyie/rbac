'use strict'

const Boom = require('boom')
const express = require('express')
const nock = require('nock')
const Rbac = require('../lib')

// Authorize server mock
const opts = {
  reqheaders: {
    authorization: /Bearer\s\S+/   // You need to pass along the token for your requests
  }
}
nock('http://www.example.com', opts)
  .post('/authorize', {
    permissions: ['users:read']
  })
  .times(1000)
  .delay(500)
  .reply(200)
  .post('/authorize', '*')
  .times(1000)
  .delay(500)
  .reply(401)

// Your server below
const rbac = new Rbac({
  remoteAuth: {
    url: 'http://www.example.com/authorize'
  }
})

const app = express()

app.get('/',
  rbac.express.authorizeRemote(['users:read']),
  (req, res, next) => {
    res.json({ message: 'You have acces to this awesome content!' })
  })

app.get('/favicon.ico', (req, res, next) => res.sendStatus(200))

app.use((err, req, res, next) => {
  if (!err.isBoom) {
    err = Boom.wrap(err)
  }
  return res
    .status(err.output.statusCode)
    .send(err.output.payload)
})

app.listen(3000, () => console.log('Listening @ 3000'))
