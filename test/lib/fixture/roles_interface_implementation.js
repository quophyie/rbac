'use strict'
var _ = require('lodash')
var Promise = require('bluebird')
var roles = [
  {
    id: 1,
    roleName: 'TEST_ROLE_1',
    permissions: [
      {
        id: 1,
        name: 'update'
      },
      {
        id: 6,
        name: 'delete'
      }
    ]
  },
  {
    id: 2,
    roleName: 'TEST_ROLE_2',
    permissions: [
      {
        id: 2,
        name: 'read'
      },
      {
        id: 4,
        name: 'write'
      }]
  },
  {
    id: 3,
    roleName: 'TEST_ROLE_3',
    permissions: [
      {
        id: 5,
        name: 'read'
      }
    ]
  },
  {
    id: 4,
    roleName: 'TEST_ROLE_1',
    permissions: [
      {
        id: 1,
        name: 'update'
      }
    ]
  }, {
    id: 5,
    roleName: 'TEST_ROLE_1',
    permissions: [
      {
        id: 2,
        name: 'read'
      }
    ]
  }
]

module.exports = {
  Roles: roles,
  RolesDalMockImplementation: {
    findById: function (id) {
      return Promise.resolve(_.find(roles, function (item) {
        return item.id === id
      })
      )
    },
    findByName: function (name) {
      return Promise.resolve(_.find(roles, function (item) {
        return item.roleName === name
      })
      )
    },
    getRolePermissionsByRoleName: function (name) {
      let permissions = []
      let _roles = []

      _roles = _.filter(roles, function (item) {
        return item.roleName === name
      })
      permissions = _.map(_roles, (role) => {
        if (role && role.permissions) {
          return role.permissions
        }
      })
      permissions = _.flatMap(permissions, (perm) => {
        return perm
      })
      return Promise.resolve(permissions)
    },
    getRolePermissionsByRoleId: function (id) {
      var role = _.find(roles, function (item) {
        return item.id === id
      })
      return Promise.resolve(role.permissions)
    },
    findRolesByPermission: function (permission) {
      var foundRoles = []
      _.forEach(roles, function (role) {
        var filtered = _.filter(role.permissions, function (role_permission) {
          return role_permission.name === permission
        })
        if (filtered && filtered.length > 0) {
          foundRoles.push(role)
        }
      })

      return Promise.resolve(foundRoles)
    },
    findAllRoles: function () {
      return Promise.resolve(roles)
    },
    getRoleName: function (role) {
      return Promise.resolve(role.roleName)
    },
    getRoleId: function (role) {
      return Promise.resolve(role.id)
    },
    getPermissionName: function (permission) {
      return Promise.resolve(permission.name)
    },
    getPermissionId: function (permission) {
      return Promise.resolve(permission.id)
    }

  }
}
