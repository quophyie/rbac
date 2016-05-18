'use strict'

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
  }
})

rbac
  .authorize(0, ['users:read'])
  .then(() => console.log('User successfuly authorized!'))
  .catch((err) => console.log('Error: Permission denied. ' + err))
