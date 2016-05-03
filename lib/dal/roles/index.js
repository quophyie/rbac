'use strict'

/**
 * Created by dman on 11/04/16.
 */
var I = require('methodical')
var _ = require('lodash')

/**
 The roles interface that the roles DAL must implement
 */
var rolesInterface = new I(
  {
    required: {
      // Returns a role using the role id. Function implementation must take a role id as the only param. Function must return a bluebird promise
      findById: I.function,
      // Returns a role using the role name. Function implementation must take a role name as the only param. Function must return a bluebird promise
      findByName: I.function,
      // Returns a role's name. Function implementation must take a role instance as the only param. Function must return a bluebird promise
      getRoleName: I.function,
      // Returns a role id using of the given role. Function implementation must take a role instance as the only param. Function must return a bluebird promise
      getRoleId: I.function,
      // Returns an array permissions of role using a role name. Function implementation must take a role name as the only param. Function must return a bluebird promise
      getRolePermissionsByRoleName: I.function,
       // Returns an array permissions of role using a role id. Function implementation must take a role id as the only param. Function must return a bluebird promise
      getRolePermissionsByRoleId: I.function,
      // Returns an array roles of of a given permission. Function implementation must take an instance of a permission as the only param. Function must return a bluebird promise
      findRolesByPermission: I.function,
      // Returns a given permission's name. Function implementation must take an instance of a permission as the only param. Function must return a bluebird promise
      getPermissionName: I.function,
      // Returns a given permission's id. Function implementation must take an instance of a permission as the only param. Function must return a bluebird promise
      getPermissionId: I.function,
      // Returns all roles in  the system. The function does not take any params. Function must return a bluebird promise
      findAllRoles: I.function,
      // Returns a role member's roles using the member id and an optional member type (e.g. Member Types i.e. 'USER', 'EXTERNAL_APPLICATION', etc). Member types are used to discriminate between the different groups / types in the role member data store /db. For example if you have an external user role members store /db  and an internal user's role members store / db, you can use the `memberType` param to tell the function how to retrieve roles for internal members and external members and hence to possibly call different retrieval services for the the different types of members. Function implementation must take the member's id and an optional member type
      findMemberRoles: I.function
    }
  })

/**
 * An instance of roles DAL which takes an implementation of the roles DAL interface
 * @param rolesDalImplementation: an implementation of the role DAL  interface
 */
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
