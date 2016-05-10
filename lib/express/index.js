/**
 * Created by dman on 15/04/16.
 */
'use strict'
const check = require('check-types')
const Enums = require('./../enum/index')
let rbacBase = null
const interceptor = require('express-interceptor')
const _ = require('lodash')
const requestPromise = require('request-promise')
var RequestPromiseErrors = require('request-promise/errors')
const Validator = require('@c8/joi-validator-promised')
const Joi = require('joi')
const parseBearerToken = require('parse-bearer-token')

const errMsgObj = {errorCode: 1100, error: 'Permission to resource denied'}
const httpErrorStatusCode = 403
let bUseRemoteAuth = false
let remoteAuthUrl = ''
const sendErrorMessage = (res, errorMsgObject) => {
  let msgObj = errMsgObj
  if (errorMsgObject) {
    msgObj = errorMsgObject
  }
  res.status(httpErrorStatusCode).json(msgObj)
}

const validateRemoteAuthorizationServerUrl = (url) => {
  const authUrlSchema = {
    url: Joi.string().uri({
      scheme: [
        'https',
        'http'
      ]
    })
  }
  const validationRes = new Validator({ stripUnknown: true }).validateSync({url: url}, authUrlSchema)

  return validationRes !== null
}

const performRemoteAuthorization = (opts, req, res, next) => {
  const bValRes = validateRemoteAuthorizationServerUrl(opts.remoteAuthorizationEndPoint)

  if (!bValRes) {
    throw new Validator.ValidationError('The property "remoteAuthorizationUrl" is required and must the full absolute url of the remote authorization server')
  }

  const permissionsSchema = {
    permissions: Joi.array()
  }
  const permissionsValRes = new Validator({ stripUnknown: true }).validateSync(_.pick(opts.permissions), permissionsSchema)

  if (permissionsValRes) {
    throw new Validator.ValidationError('The property "permissions" is required and must be a string array of permissions')
  }

  let rbacAction = Enums.Rbac.Action.Allow

  if (opts.requestedAction) {
    const actionSchema = {
      requestedAction: Joi.string()
    }

    const actionValRes = new Validator({ stripUnknown: true }).validateSync(_.pick(opts.requestedAction), actionSchema)

    if (actionValRes) {
      throw new Validator.ValidationError('The property "requestedAction" must be of type string')
    } else {
      rbacAction = opts.requestedAction.toLowerCase()
    }
  }

  const token = parseBearerToken(req)
  let scheme = 'http'
  let urlPrefix = ''
  if (!_.startsWith(opts.remoteAuthorizationEndPoint.toLowerCase().trim(), 'http:') || !_.startsWith(opts.remoteAuthorizationEndPoint.toLowerCase().trim(), 'https:')) {
    urlPrefix = `${scheme}://`
  }
  const endPoint = `${urlPrefix}${opts.remoteAuthorizationEndPoint.trim()}`

  // request remote authorization
  requestPromise.post(endPoint, {
    auth: {
      'bearer': token
    },
    json: true,
    body: {
      c8rbac: {
        permissions: opts.permissions,
        permissionsGroup: opts.permissionsGroup,
        requestedAction: rbacAction,
        user: req.user
      }
    }

  }).then(
    (body) => {
      if (body && check.boolean(body.requestedActionResult)) {
        let bCallNext = false
        if (body.requestedActionResult === true) {
          if (rbacAction.toLowerCase() === Enums.Rbac.Action.Allow.toLowerCase()) {
            bCallNext = true
          } else if (rbacAction.toLowerCase() === Enums.Rbac.Action.Deny.toLowerCase()) {
            bCallNext = false
          }
        }
        // authorisation success so call next
        if (bCallNext === true) {
          next()
        } else {
          // authorisation failed so send error response
          sendErrorMessage(res)
        }
      }
    }).catch(RequestPromiseErrors.StatusCodeError, (error) => {
      let err = {message: error.message, statusCode: error.statusCode, statusMessage: error.statusMessage}
      next(JSON.stringify(err))
    })
    .catch(RequestPromiseErrors.RequestError, (error) => {
      let err = {message: error.message, statusCode: error.statusCode, statusMessage: error.statusMessage}
      next(JSON.stringify(err))
    }).catch((err) => {
      next(err)
    })
}
const Express = {
  /**
   * Iniitalises RbacExpress module. This must be called to initialise the RbacExpress module
   * before any other methods are called
   * @param {object} opts - Options for RbacExpress. It should at the  very least provide an implementation of roles DAL
   * and Users DAL and optionally a 'dfefaultAction' property which can have a value of `permit` or `deny`
   * for example
    const opts = {
     RolesDal: {
        findById: (roleId) => { return role},
        findByName: (roleName) => { return role},
        getRoleName: (role) => { return roleName},
        getRoleId: (role) => { return roleId},
        getRolePermissionsByRoleName:  (roleName) => { return rolePermissions},
        getRolePermissionsByRoleId:  (roleId) => { return rolePermissions},
        findRolesByPermission: (permission) => { return roles },
        getPermissionName:  (permission) => { return rolePermissionName},
        getPermissionId:  (permission) => { return permissionId},
        findAllRoles:() => { return roles}
    },
     UsersDal: {
    findUserById:(userId) => { return user},
    getUserRolesByUserId: (userId) => { return userRoles}
   },
   defaultAction : 'deny'
   }
   * @param app:  an instance of the express app
   * @returns: an express middleware
   */
  initialize: (opts, app) => {
    // var _app = app
    if (!opts) {
      opts = {
        defaultAction: 'deny'
      }
      bUseRemoteAuth = false
    }

    if (opts.useRemoteAuthorization === true || opts.useRemoteAuthorization === false) {
      bUseRemoteAuth = opts.useRemoteAuthorization
    }

    // If using remote authorization, then check and make sure that remoteAuthorizationServerUrl is a valid  url
    if (bUseRemoteAuth) {
      const bValRes = validateRemoteAuthorizationServerUrl(opts.remoteAuthorizationEndPoint)

      if (!bValRes) {
        throw new Validator.ValidationError('The opts property "RemoteAuthorizationUrl" is required and must the full absolute url of the remote authorization server')
      } else {
        remoteAuthUrl = opts.remoteAuthorizationEndPoint
      }
    }

    if (!opts.defaultAction) {
      opts.defaultAction = Enums.Rbac.Action.Deny.toLowerCase()
    }

    if (!check.string(opts.defaultAction)) {
      throw new TypeError('opts.defaultAction must be of type String')
    } else {
      if (!check.match(opts.defaultAction.toLowerCase(), /deny/) && !check.match(opts.defaultAction.toLowerCase(), /permit/)) {
        throw new TypeError('opts.defaultAction must have a value of "deny" or "permit"')
      }
    }
    let rolesDalImpl = null
    const RolesDal = require('./../index').Dal.RolesDal
    const RbacBase = require('./../index').RbacBase
    if (opts.RolesDal) {
      rolesDalImpl = new RolesDal(opts.RolesDal)
    }

    rbacBase = new RbacBase(rolesDalImpl)
    rbacBase.initialize()
    // let isDenied = false
    return interceptor((req, res, next) => {
      return {
        // Only HTML responses will be intercepted
        isInterceptable: () => {
          // isDenied = false
          if (req.body && req.body.c8rbac !== undefined && req.body.c8rbac !== null) {
            if (req.body.c8rbac.isRbacProcessed === false) {
              // If the c8rbac object was not provided in remote rbac request,  the delete the c8rbac object
              if (req.body.c8rbac.isC8RbacProvidedInRemoteRbacRequest === false) {
                delete req.body.c8rbac
              }
              if (opts.defaultAction.toLowerCase() === Enums.Rbac.Action.Deny.toLowerCase()) {
                res.status(httpErrorStatusCode
                )
                return true
              } else {
                // We return and dont call next because tamper takes care of calling next for us
                return false
              }
            } else {
              // Return false if we dont want to intercept the response body
              return false
            }
          } else { // The request has already gone through rbac pipleline so call the next middleware
            if (opts.defaultAction.toLowerCase() === Enums.Rbac.Action.Deny.toLowerCase()) {
              res.status(httpErrorStatusCode)
              // sendErrorMessage(res)
              // isDenied = true
              return true
            } else {
              // We return and dont call next because tamper takes care of calling next for us
              return false
            }
          }
        },
        // intercept all calls where it isInterceptable returns true
        intercept: (body, send) => {
          send(JSON.stringify(errMsgObj))
        }
      }
    })
  },

  /**
   * Allows access to the next middleware if the user has one of the permissions in the permissions array
   * @param permissions: an array of permissions which allow access to the next middleware
   * @param opts:
   *          permissionsGroup:
   *              The permission group to which the array of permissions belong (for e.g. 'Credentials', 'UsersAccess' etc). If you are unsure, then dont provide this parameter,
   *               in which case the permission will added to the 'DEFAULT' permissions group
   *          useRemoteAuthorization: This a a boolean that determines whether to delegate authorisation a remote server. If
   *                                  `useRemoteAuthorization` is set to true, then, you must set the value of `remoteAuthorizationEndpoint`,
   *                                  to the endpoint on the remote server that is to perform the authorization
   *          remoteAuthorizationEndpoint: The full absolute url of remote server that is to perform the remote authorization
   * @returns express middleware
   */
  allow: (permissions, opts) => {
    return (req, res, next) => {
      if (!rbacBase) {
        throw Error('RbacExpress has not been initialised. Did you forget to call method "RbacExpress.initialize"')
      }

      const permissionsSchema = {
        permissions: Joi.array()
      }
      const permissionsValRes = new Validator({ stripUnknown: true }).validateSync({permissions: permissions}, permissionsSchema)

      if (permissionsValRes) {
        throw new Validator.ValidationError('The parameter "permissions" is required and must be a string array of permissions')
      }

      let bUseRemAuth = bUseRemoteAuth
      let remAuthUrl = remoteAuthUrl
      if (opts) {
        if (opts.useRemoteAuthorization && check.boolean(opts.useRemoteAuthorization)) {
          bUseRemAuth = opts.useRemoteAuthorization
        } else {
          throw new Validator.ValidationError('The parameter "opts.useRemoteAuthorization" must be of type boolean')
        }
        if (opts.remoteAuthorizationEndPoint && check.string(opts.remoteAuthorizationEndPoint)) {
          remAuthUrl = opts.remoteAuthorizationEndPoint
        } else {
          throw new Validator.ValidationError('The parameter "opts.remoteAuthorizationEndpoint" must be of type String')
        }
      }
      const permissionsGroup = opts ? opts.permissionsGroup : null
      if (bUseRemAuth) {
        let remoteAuthorizationOpts = {
          remoteAuthorizationEndPoint: remAuthUrl,
          permissions: permissions,
          permissionsGroup: permissionsGroup,
          requestedAction: Enums.Rbac.Action.Allow.toLowerCase(),
          user: req.user
        }
        performRemoteAuthorization(remoteAuthorizationOpts, req, res, next)
      } else {
        if (req.user && req.user.id) {
          rbacBase.permit(req.user.id, req.user.target, permissions, permissionsGroup)
            .then((bIsAllowed) => {
              // Set isProcessed to true to indicate that that the request has gone through the rbac pipeline
              req.body.c8rbac = {isRbacProcessed: true}
              if (bIsAllowed) {
                next()
              } else {
                sendErrorMessage(res)
              }
            }).catch((err) => {
              next(err)
            })
        } else {
          // Set isProcessed to true to indicate that that the request has gone through the rbac pipeline
          req.body.c8rbac = {isRbacProcessed: true}
          sendErrorMessage(res)
        }
      }
    }
  },
  /**
   * Denies access to the next middleware (i.e. the next middleware is not called) if the user has one of the permissions in the permissions array
   * @param permissions: an array of permissions which allow access to the next middleware
   * @param opts:
   *          permissionsGroup:
   *              The permission group to which the array of permissions belong (for e.g. 'Credentials', 'UsersAccess' etc). If you are unsure, then dont provide this parameter,
   *               in which case the permission will added to the 'DEFAULT' permissions group
   *          useRemoteAuthorization: This a a boolean that determines whether to delegate authorisation a remote server. If
   *                                  `useRemoteAuthorization` is set to true, then, you must set the value of `remoteAuthorizationEndpoint`,
   *                                  to the endpoint on the remote server that is to perform the authorization
   *          remoteAuthorizationEndpoint: The full absolute url of remote server that is to perform the remote authorization
   * @returns express middleware
   */
  deny: (permissions, opts) => {
    if (!rbacBase) {
      throw Error('RbacExpress has not been initialised. Did you forget to call method "RbacExpress.initialize"')
    }
    return (req, res, next) => {
      const permissionsSchema = {
        permissions: Joi.array()
      }
      const permissionsValRes = new Validator({ stripUnknown: true }).validateSync({permissions: permissions}, permissionsSchema)

      if (permissionsValRes) {
        throw new Validator.ValidationError('The parameter "permissions" is required and must be a string array of permissions')
      }

      let bUseRemAuth = bUseRemoteAuth
      let remAuthUrl = remoteAuthUrl
      if (opts) {
        if (opts.useRemoteAuthorization && check.boolean(opts.useRemoteAuthorization)) {
          bUseRemAuth = opts.useRemoteAuthorization
        } else {
          throw new Validator.ValidationError('The parameter "opts.useRemoteAuthorization" must be of type boolean')
        }
        if (opts.remoteAuthorizationEndPoint && check.string(opts.remoteAuthorizationEndPoint)) {
          remAuthUrl = opts.remoteAuthorizationEndPoint
        } else {
          throw new Validator.ValidationError('The parameter "opts.remoteAuthorizationEndpoint" must be of type String')
        }
      }
      const permissionsGroup = opts ? opts.permissionsGroup : null
      if (bUseRemAuth) {
        let remoteAuthorizationOpts = {
          remoteAuthorizationEndPoint: remAuthUrl,
          permissions: permissions,
          permissionsGroup: permissionsGroup,
          requestedAction: Enums.Rbac.Action.Deny.toLowerCase(),
          user: req.user
        }
        performRemoteAuthorization(remoteAuthorizationOpts, req, res, next)
      } else {
        if (req.user && req.user.id) {
          rbacBase.deny(req.user.id, req.user.target, permissions, permissionsGroup)
            .then((bIsDenied) => {
              // Set isProcessed to true to indicate that that the request has gone through the rbac pipeline
              req.body.c8rbac = {isRbacProcessed: true}
              if (bIsDenied) {
                sendErrorMessage(res)
              } else {
                next()
              }
            }).catch((err) => {
              next(err)
            })
        } else {
          // Set isProcessed to true to indicate that that the request has gone through the rbac pipeline
          req.body.c8rbac = {isRbacProcessed: true}
          sendErrorMessage(res)
        }
      }
    }
  },
  /**
   * This method is used to verify remote RBAC requests
   * @param req: the request object. The request object must contain object 'body.c8rbac' where the 'body.c8rbac' object must have a
   * REQUIRED property called `permissions` which is a set of permissions which is to tested agains the role permissions of the user.
   * The 'body.c8rbac' object  can also specify an optional `action` property with a value of either 'allow' or 'deny'
   * which specifies the requested action on `RBAC`. If the
   * optional `action` property is not specified, then the default action will be set as 'allow'. Finally, the 'body.c8rbac' object
   * can also specify an optional `permissionsGroup` property. The permissionsGroup` specifies the permission group to which
   * the array of permissions belong (for e.g. 'Credentials', 'UsersAccess' etc). If you are unsure, then dont provide this parameter,
   * in which case the permission will added to the 'DEFAULT' permissions group.
   * A full 'body.c8rbac' object will look like
   * ```js
   *   {
   *      permissions:['user_admin', 'create_user'],  //REQUIRED Property
   *      requestedAction: 'allow', //OPTIONAL Property
   *      permissionGroup: 'DEFAULT' //OPTIONAL Property
   *   }
   * ```
   */
  verify: () => {
    return (req, res, next) => {
      let errMsgObj = null
      let promise = null
      if (req.body && req.body.c8rbac) {
        let c8rbac = req.body.c8rbac
        if (c8rbac.permissions) {
          let permissions = c8rbac.permissions
          let permissionsGroup = c8rbac.permissionsGroup
          let rbacAction = Enums.Rbac.Action.Allow
          if (c8rbac.requestedAction) {
            rbacAction = c8rbac.requestedAction
          }

          const validRbacActionsRegexPattern = _.join(_.values(Enums.Rbac.Action), '|')
          if (!check.string(rbacAction) || !check.match(rbacAction, validRbacActionsRegexPattern)) {
            errMsgObj = {
              errorCode: 1102,
              error: 'Invalid Rbac action. The Rbac action must be one of the following values: ' + _.join(_.values(Enums.Rbac.Action, ', '))
            }
            return sendErrorMessage(res, errMsgObj)
          }
          if (rbacAction.toLowerCase() === Enums.Rbac.Action.Allow.toLowerCase()) {
            promise = rbacBase.permit(c8rbac.user.id, c8rbac.user.target, permissions, permissionsGroup)
          } else if (rbacAction.toLowerCase() === Enums.Rbac.Action.Deny.toLowerCase()) {
            promise = rbacBase.deny(c8rbac.user.id, c8rbac.user.target, permissions, permissionsGroup)
          }

          promise.then((bRbacActionResult) => {
            res.send({requestedActionResult: bRbacActionResult})
          })
            .catch((err) => {
              res.status(400).json(JSON.stringify(err))
            })
        } else {
          errMsgObj = {
            errorCode: 1103,
            requestedActionResult: false,
            error: 'Permissions not provided for the requested RBAC action'
          }
          return sendErrorMessage(res, errMsgObj)
        }
      } else {
        // We ony create the c8rbac here so as to pass some data to that is ised by the initialize method
        // This c8rbac will be DELETED by the initialise method if req.body.c8rbac was originally null or undefined
        req.body.c8rbac = {isC8RbacProvidedInRemoteRbacRequest: false, isRbacProcessed: true}
        errMsgObj = {
          errorCode: 1101,
          requestedActionResult: false,
          error: 'Permission to resource denied. Could not find object "c8rbac" on req.body'
        }
        return sendErrorMessage(res, errMsgObj)
      }
    }
  }
}

module.exports = Express
