/**
 * Created by dman on 14/04/16.
 */
'use strict'
const Roles = require('./roles_interface_implementation').Roles
const Promise = require('bluebird')
const _ = require('lodash')

let users = [
  {
    id: 1,
    email: 'superman@c8management.com',
    roles: [Roles[0], Roles[2]]
  },
  {
    id: 2,
    email: 'batman@c8management.com',
    roles: [Roles[2]]
  }
]

module.exports = {
  Users: users,
  UsersDalMockImplementation: {
    findUserById: (id) => {
      let foundUser = _.find(users, (user) => {
        return user.id === id
      })

      return Promise.resolve(foundUser)
    },
    getUserRolesByUserId: (id) => {
      let foundUser = _.find(users, (user) => {
        return user.id === id
      })

      return Promise.resolve(foundUser.roles)
    }
  }
}
