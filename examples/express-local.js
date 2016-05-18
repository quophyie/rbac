'use strict'

const Boom = require('boom')
const express = require('express')
const Rbac = require('../lib')

const rbac = new Rbac({
  checkPermission: function (userId, permission) {
    const users = [
      {  // user 0
        'users:create': true,
        'users:remove': true
      },
      { // users 1
        'users:read': true
      }
    ]

    const found = permission.some((p) => {
      return users[userId] && users[userId][p]
    })

    if (found) {
      return Promise.resolve()
    } else {
      return Promise.reject(new Error('Inexistent User or Permission'))
    }
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

app.use((err, req, res, next) => {
  if (!err.isBoom) {
    err = Boom.wrap(err)
  }
  return res
    .status(err.output.statusCode)
    .send(err.output.payload)
})

app.listen(3000, () => console.log('Listening @ 3000'))
