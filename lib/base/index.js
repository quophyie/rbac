'use strict'
const _ = require('lodash')
const Rbac = require('rbac-core')
const check = require('check-types')
const Promise = require('bluebird')

const DataRetrievalRouter = Rbac.DataRetrievalRouter
const dataRetrieverRouter = new DataRetrievalRouter()

let rules = {}
let usersDal = null
let rolesDal = null
let permissionsGroup = null
let self = null
let conjunctedPermissions = []
// the permissions for associated with  rule
let _conjuction = false

function RbacBase (rolesDalImpl, usersDalImpl, permsGroup, conjunction) {
  const RolesDal = require('./../dal/index').RolesDal
  const UsersDal = require('./../dal/index').UsersDal
  conjunctedPermissions = []

  if (!(rolesDalImpl instanceof RolesDal)) {
    throw new TypeError('Parameter "rolesDalImpl" must be of Type "RolesDal"')
  } else {
    rolesDal = rolesDalImpl
  }

  if (!(usersDalImpl instanceof UsersDal)) {
    throw new TypeError('Parameter "usersDalImpl" must be of Type "UsersDal"')
  } else {
    usersDal = usersDalImpl
  }

  if (conjunction !== undefined && conjunction !== null && !check.boolean(conjunction)) {
    throw new TypeError('Parameter "conjunction" must be of Type "Boolean"')
  } else if (conjunction) {
    _conjuction = conjunction
  } else if (conjunction === undefined || conjunction === null) {
    _conjuction = false
  }

  if (permsGroup) {
    let isString = check.string(permsGroup)
    if (!isString) {
      throw new TypeError('Parameter "permissionsGroup" must be of Type "String"')
    } else {
      permissionsGroup = permsGroup
    }
  } else {
    permissionsGroup = 'DEFAULT'
  }

  self = this
}

RbacBase.prototype.init = function () {
  rules = {}

  // Private methods

  /**
   @rolesDalImpl: An implentation of the RolesDal interface that is used to access roles and permissions from a datasource
   @ruleName: The name of the role whose permissions are to be added
   @conjunction: a boolean telling whether all permissions must by ANDed or ORed when testing validity to access resource
   @returns {Promise}
   */
  let createRulePermissions = (rolesDal, roleName, permissionsGroup, conjunction) => {
    if (!check.string(roleName)) {
      throw new TypeError('Parameter "roleName" must be of Type "String"')
    }
    if (!check.string(permissionsGroup)) {
      throw new TypeError('Parameter "permissionsGroup" must be of Type "String"')
    }
    if ((conjunction !== undefined || conjunction !== null) && !check.boolean(conjunction)) {
      throw new TypeError('Parameter "conjunction" must be of Type "Boolean"')
    } else if (conjunction === undefined || conjunction === null) {
      conjunction = false
    }

    return new Promise(function (resolve, reject) {
      rolesDal.getRolePermissionsByRoleName(roleName)
        .then(function (permissions) {
          let rulekey = permissionsGroup + ':' + roleName
          let numPermissionsAdded = 0
          let rulePermissions = []
          _.forEach(permissions, function (permission) {
            rolesDal.getPermissionName(permission).then((permissionName) => {
              numPermissionsAdded++
              // Only add permissions that are not in rulePermissions  array
              if (permissionName && rulePermissions.indexOf(permissionName.toLowerCase()) === -1) {
                let existingPermission = null
                if (conjunction) {
                  existingPermission = _.find(conjunctedPermissions, (perm) => {
                    return permissionName.toLowerCase() === perm.toLowerCase()
                  })
                  // only add permissions that do not alredy exist to conjunctedPermissions
                  if (!existingPermission) {
                    conjunctedPermissions.push(permissionName.toLowerCase())
                  }
                } else {
                  let permObj = {}
                  permObj[rulekey] = permissionName.toLowerCase()
                  existingPermission = _.find(rulePermissions, function (item) {
                    if (item[rulekey] && item[rulekey] === permissionName) {
                      return true
                    }
                  })
                  // only add permissions that do not alredy exist to rulePermissions
                  if (!existingPermission) {
                    rulePermissions.push(permObj)
                  }
                }
              }

              if (numPermissionsAdded === permissions.length) {
                // add the conjuncted permissions to the rulePermissions
                if (conjunction) {
                  let permObj = {}
                  permObj[rulekey] = conjunctedPermissions
                  let existingPermObj = _.find(rulePermissions, function (item) {
                    if (item[rulekey] && item[rulekey] === permObj[rulekey]) {
                      return true
                    }
                  })

                  if (!existingPermObj) {
                    rulePermissions.push(permObj)
                  }
                }
                resolve(rulePermissions)
              }
            })
          })
        })
    })
  }

  let updateRule = (ruleKey, rulePermissions, conjunction) => {
    if (!check.string(ruleKey)) {
      throw new TypeError('Parameter "roleName" must be of Type "String"')
    }
    if (!check.array(rulePermissions)) {
      throw new TypeError('Parameter "rulePermissions" must be of Type "Array"')
    }
    if (conjunction !== undefined && conjunction !== undefined && !check.boolean(conjunction)) {
      throw new TypeError('Parameter "conjunction" must be of Type "Boolean"')
    } else {
      conjunction = false
    }

    let rule = null
    if (rules[ruleKey]) {
      rule = rules[ruleKey]
      if (rule && rule.target) {
        let newPermissionsToAdd = null
        if (conjunction) {
          // Get all permissions that are not in the rules array
          newPermissionsToAdd = _.differenceWith(rulePermissions, rule.target, function (permObjForUpdate, existingPermObj) {
            if (permObjForUpdate[ruleKey] !== undefined && existingPermObj[ruleKey] !== undefined) {
              let result = _.difference(permObjForUpdate, existingPermObj)
              return (result !== undefined || result !== undefined) && result.length > 0
            }
          })
        } else {
          newPermissionsToAdd = _.differenceWith(rulePermissions, rule.target, function (permObjForUpdate, existingPermObj) {
            return permObjForUpdate[ruleKey] !== undefined && existingPermObj[ruleKey] !== undefined && permObjForUpdate[ruleKey] === existingPermObj[ruleKey]
          })
        }

        // Add any new permissions
        if (newPermissionsToAdd && newPermissionsToAdd.length > 0) {
          rule.target = _.concat(rule.target, rulePermissions)
        }
      }
    }

    return Promise.resolve(rule)
  }

  let configureRule = (rolesDal, roleName, permissionsGroup, conjunction, ruleKey) => {
    if (conjunction !== undefined && !check.boolean(conjunction)) {
      throw new TypeError('Parameter "conjunction" must be of Type "Boolean"')
    }
    return createRulePermissions(rolesDal, roleName, permissionsGroup, conjunction, ruleKey)
      .then(function (rulePermissions) {
        if (rules[ruleKey] === undefined || rules[ruleKey] === null) {
          return createAndRuleToRulesCollection(ruleKey, rulePermissions, conjunction)
        } else {
          return updateRule(ruleKey, rulePermissions, conjunction)
        }
      })
  }

  /**
   @ruleKey: The key that is used to identify the rule in rules array. Must be of the form '[permissionGroup]:[roleName]' e.g. DEFAULT:testRole
   @rulePermissions: a string array of permissions for the given role e.g. ['read', 'write']
   */
  let createAndRuleToRulesCollection = (ruleKey, rulePermissions, conjunction) => {
    if (!check.string(ruleKey)) {
      throw new TypeError('Parameter "roleName" must be of Type "String"')
    }
    if (!check.array(rulePermissions)) {
      throw new TypeError('Parameter "rulePermissions" must be of Type "Array"')
    }
    if (conjunction !== undefined && conjunction !== null && !check.boolean(conjunction)) {
      throw new TypeError('Parameter "conjunction" must be of Type "Boolean"')
    }
    if (rules[ruleKey] === undefined || rules[ruleKey] === null) {
      rules[ruleKey] = {
        target: rulePermissions,
        effect: 'permit'
      }
    }
    return Promise.resolve(rules[ruleKey])
  }

  const configure = (_rolesDal) => {
    let numOfConfiguredRoles = 0
    return new Promise((resolve, reject) => {
      _rolesDal.findAllRoles()
        .then(function (roles) {
          if (roles && roles instanceof Array) {
            _.forEach(roles, function (role) {
              _rolesDal.getRoleName(role).then(function (roleName) {
                if (roleName && check.string(roleName)) {
                  // the role name has not been registered with the rules array, then register it
                  let ruleKey = permissionsGroup + ':' + roleName
                  if (rules[ruleKey] === undefined || rules[ruleKey] === null) {
                    let conjunction = _conjuction // all permissions should be ORed
                    configureRule(rolesDal, roleName, permissionsGroup, conjunction, ruleKey)
                      .then(function () {
                        // now register the permissions group with the  dataRetrieverRouter
                        dataRetrieverRouter.register(permissionsGroup, (source, key, context) => {
                          // Obtain your value (e.g. from the context)
                          const value = context[key]
                          return value
                        }, { override: true })

                        // now register the permissions group with the  dataRetrieverRouter
                        /* registerPermissionGroupWithDataRetrieveRouter(permissionsGroup, (source, key, context) => {
                         // Obtain your value (e.g. from the context)
                         const value = context[key]
                         return value
                                              }) */
                        return Promise.resolve()
                      }).then(() => {
                        numOfConfiguredRoles++
                        if (numOfConfiguredRoles === roles.length) {
                          return resolve()
                        }
                      }).catch((err) => {
                        return reject(err)
                      })
                  }
                } else {
                  throw new TypeError('Role names must be of Type "String"')
                }
              })
            })
          }
        }).catch((err) => {
          return reject(err)
        })
    })
  }
  return configure(rolesDal)
}

RbacBase.prototype.permit = (userId, permissionNames, permGroup) => {
  if (!permissionNames) {
    return Promise.resolve(false)
  }
  if (permissionNames && !check.array(permissionNames)) {
    return Promise.reject(new TypeError('Parameter "permissionNames" must be of type Array'))
  }
  return new Promise((resolve, reject) => {
    let bExit = false
    let rulekey = ''
    usersDal.getUserRolesByUserId(userId).then((roles) => {
      _.forEach(roles, (role) => {
        return rolesDal.getRoleName(role).then((roleName) => {
          // Get the rule key
          if (!permGroup) {
            // Use the default scheme to generate the rule key
            rulekey = permissionsGroup + ':' + roleName
          } else {
            rulekey = permGroup + ':' + roleName
          }
          let rule = rules[rulekey]
          if (rule) {
            let information = {}
            information[roleName] = permissionNames
            // Evaluate the the rules / policies
            Rbac.evaluatePolicy(rule, dataRetrieverRouter.createChild(information), (err, result) => {
              if (err) {
                return reject(err)
              }
              switch (result) {
                case Rbac.PERMIT:
                  {
                    bExit = true
                    resolve(true)
                    break
                  }
                default:
                  {
                    resolve(false)
                    break
                  }
              }
            })
          } else {
            bExit = true
            resolve(true)
          }
          // break out  of the forEach loop
          if (bExit) {
            return false
          }
        })
      })
    }).catch((err) => {
      return reject(err)
    })
  })
}

RbacBase.prototype.getRules = () => {
  return Promise.resolve(rules)
}
RbacBase.prototype.deny = (userId, permissions, permissionsGroup) => {
  return new Promise((resolve, reject) => {
    return self.permit(userId, permissions, permissionsGroup).then((permitted) => {
      resolve(permitted)
    }).catch((err) => {
      return reject(err)
    })
  })
}

module.exports = RbacBase
