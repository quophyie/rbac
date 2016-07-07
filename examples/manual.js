'use strict'

const Rbac = require('../lib')

const rbac = new Rbac({
  checkPermission: function (id, permissions) {
    return new Promise((resolve, reject) => {
      const users = [
        { // user 0
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
})

rbac
  .authorize(0, ['users:read'])
  .then(() => console.log('User successfuly authorized!'))
  .catch((err) => console.log('Error: Permission denied. ' + err))
