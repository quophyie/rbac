/**
 * Created by dman on 15/04/16.
 */
'use strict'
const check = require('check-types')
let rbacBase = null
// var onHeaders = require('on-headers')
var interceptor = require('express-interceptor')
// var tamper = require('tamper')
// var bafMiddleware = require('before-and-after')

const errMsgObj = {error_code: 1100, error: 'Permission to resource denied'}
const httpErrorStatusCode = 403
const sendErrorMessage = (res) => {
  res.status(httpErrorStatusCode).json(errMsgObj)
}
const Express = {
  /**
   * (description)
   * 
   * @param opts (description)
   * @param app (description)
   * @returns (description)
   */
  initialize: (opts, app) => {
    // var _app = app
    if (!opts) {
      opts = {
        defaultAction: 'deny'
      }
    }

    if (!opts.defaultAction) {
      opts.defaultAction = 'deny'
    }

    if (!check.string(opts.defaultAction)) {
      throw new TypeError('opts.defaultAction must be of type String')
    } else {
      if (!check.match(opts.defaultAction.toLowerCase(), /deny/) && !check.match(opts.defaultAction.toLowerCase(), /permit/)) {
        throw new TypeError('opts.defaultAction must have a value of "deny" or "permit"')
      }
    }
    let rolesDalImpl = null
    let usersDalImpl = null
    const RolesDal = require('./../index').Dal.RolesDal
    const UsersDal = require('./../index').Dal.UsersDal
    const RbacBase = require('./../index').RbacBase
    if (opts.RolesDal) {
      rolesDalImpl = new RolesDal(opts.RolesDal)
    }

    if (opts.UsersDal) {
      usersDalImpl = new UsersDal(opts.UsersDal)
    }
    rbacBase = new RbacBase(rolesDalImpl, usersDalImpl)
    rbacBase.initialize()
    // let isDenied = false
    return interceptor((req, res, next) => {
      return {

        // Only HTML responses will be intercepted
        isInterceptable: () => {
          // isDenied = false
          if (req.body && req.body.c8rbac !== undefined && req.body.c8rbac !== null) {
            if (req.body.c8rbac.isProcessed === false) {
              if (opts.defaultAction === 'deny') {
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
            if (opts.defaultAction === 'deny') {
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
  allow: (permissions, permissionsGroup) => {
    return (req, res, next) => {
      if (!rbacBase) {
        throw Error('RbacExpress has not been initialised. Did you forget to call method "RbacExpress.express"')
      }
      if (req.user && req.user.id) {
        rbacBase.permit(req.user.id, permissions, permissionsGroup)
          .then((bIsAllowed) => {
            // Set isProcessed to true to indicate that that the request has gone through the rbac pipeline
            req.body.c8rbac = {isProcessed: true}
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
        req.body.c8rbac = {isProcessed: true}
        sendErrorMessage(res)
      }
    }
  },
  deny: (permissions, permissionsGroup) => {
    if (!rbacBase) {
      throw Error('RbacExpress has not been initialised. Did you forget to call method "RbacExpress.express"')
    }
    return (req, res, next) => {
      if (req.user && req.user.id) {
        rbacBase.deny(req.user.id, permissions, permissionsGroup)
          .then((bIsDenied) => {
            // Set isProcessed to true to indicate that that the request has gone through the rbac pipeline
            req.body.c8rbac = {isProcessed: true}
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
        req.body.c8rbac = {isProcessed: true}
        sendErrorMessage(res)
      }
    }
  }
}
module.exports = Express

/**
 * return tamper((req, res, next) => {
      let isDenied = false
      // If the request has not gone through the rbac pipe i.e. req.body.c8rbac.isProcessed === false appy the default action
      if (req.body && req.body.c8rbac !== undefined && req.body.c8rbac !== null) {
        if (req.body.c8rbac.isProcessed === false) {
          if (opts.defaultAction === 'deny') {
            isDenied = true
            // res.status(httpErrorStatusCode)
            //sendErrorMessage(res)
            return
          } else {
            // We return and dont call next because tamper takes care of calling next for us
            return
          }
        } else {
          // We return and dont call next because tamper takes care of calling next for us
          return
        }
      } else { // The request has already gone through rbac pipleline so call the next middleware
        if (opts.defaultAction === 'deny') {
          res.status(httpErrorStatusCode)
          isDenied = true
            //sendErrorMessage(res)
             return
        } else {
          // We return and dont call next because tamper takes care of calling next for us
          return
        }
      }
      return function (body) {
        if (isDenied) {
          return JSON.stringify(errMsgObj)
        } else {
          return body
        }
      }
    })
 */

/**
 *return interceptor(function(req, res, next){
       var isDenied  = false
       onHeaders(res, () => {
        if (isDenied) {
          sendErrorMessage(res)
          isDenied = false
        }
       })
       return {
         // Only HTML responses will be intercepted
         isInterceptable: function(){
           if (req.body && req.body.c8rbac !== undefined && req.body.c8rbac !== null) {
             if (req.body.c8rbac.isProcessed === false) {
               if (opts.defaultAction === 'deny') {
                 res.status(httpErrorStatusCode)
                 //sendErrorMessage(res)
                 return true
               } else {
                 // We return and dont call next because tamper takes care of calling next for us
                 return false
               }
             } else {
               // We return and dont call next because tamper takes care of calling next for us
               return false
             }
           } else { // The request has already gone through rbac pipleline so call the next middleware
             if (opts.defaultAction === 'deny') {
               res.status(httpErrorStatusCode)
              // sendErrorMessage(res)
              // isDenied = true
               return true
             } else {
               // We return and dont call next because tamper takes care of calling next for us
               return  false
             }
           }
           //   return true
         },
         // Appends a paragraph at the end of the response body
         intercept: function(body, send) {
           send(JSON.stringify(errMsgObj))
         }
       }
     })

 */