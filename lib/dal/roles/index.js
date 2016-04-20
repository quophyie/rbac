'use strict'

/**
 * Created by dman on 11/04/16.
 */
var I = require('methodical')
var _ = require('lodash')
var rolesInterface = new I(
  {
    required: {
      findById: I.function,
      findByName: I.function,
      getRoleName: I.function,
      getRoleId: I.function,
      getRolePermissionsByRoleName: I.function,
      getRolePermissionsByRoleId: I.function,
      findRolesByPermission: I.function,
      getPermissionName: I.function,
      getPermissionId: I.function,
      findAllRoles: I.function
    }
  })

function RolesDal (rolesDalImplementation) {
  // Will throw an exception if the roles interface above is not  implemented
  rolesInterface.check(rolesDalImplementation)
  if (this.prototype) {
    this.prototype = _.assign(this.prototype, rolesDalImplementation)
  } else {
    _.assign(this, rolesDalImplementation)
  }
}

module.exports = RolesDal
