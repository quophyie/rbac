'use strict'

const Boom = require('boom')
const express = require('express')
const nock = require('nock')
const Rbac = require('../lib')

// Authorize server mock
nock('http://www.example.com')
  .post('/authorize', {
    userId: 1,
    permission: ['users:read']
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
  },
  reqUserId: 'params.userId'
})

const app = express()

app.get('/:userId',
  // You probably want to authenticate the user first.
  rbac.express.authorize(['users:read']),
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
