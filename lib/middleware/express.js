'use strict'

const Boom = require('boom')
const Hoek = require('hoek')

class Express {
  /**
   * Creates a new Express middleware instance, bounded to a specific Rbac object.
   * @param rbac
   */
  constructor (rbac) {
    this._rbac = rbac
  }

  /**
   * Returns an express middleware function for checking if the principal who made the request is authorized for any of
   * the given permissions. Parameters are the same as `rbac.authorize`, except for the `id` parameter which can be
   * setup in the constructor options via the `getReqId` callback. Note that this middleware also sets the authorization
   * header with the current request's header, for remote authorization. If you don't want this behaviour, set it to
   * `undefined` in `opts`.
   * @param {array} permissions - The permissions to check against the user.
   * @param {object} [opts] - Optional options to be passed to the function. Same properties as the constructor.
   * @returns {function} - An express middleware signature function.
   */
  authorize (permissions, opts) {
    Hoek.assert(Array.isArray(permissions), new TypeError('Invalid permissions value: must be an array'))

    const rbac = this._rbac
    return function (req, res, next) {
      // Getters for Principal ID and type
      let getReqId
      let getReqType
      if (opts) {
        getReqId = opts.getReqId || rbac._opts.getReqId
        getReqType = opts.getReqType || rbac._opts.getReqType
      } else {
        getReqId = rbac._opts.getReqId
        getReqType = rbac._opts.getReqType
      }

      // Get Principal ID and type from request. They are required to proceed with authorization.
      const id = getReqId(req)
      const type = getReqType(req)
      if (!id || !type) {
        return next(Boom.unauthorized('Inexistent Principal id or type.'))
      }

      // If options are set for remote authorization, setup the authorization header.
      if (rbac._opts.principals[type].remoteAuth ||
        (opts && typeof opts.principals[type].remoteAuth === 'object')) {
        const optsWithAuthHeader = {
          principals:{
            [type]: {
              remoteAuth: {
                headers: {
                  // Forwards the authorization header.
                  // FIXME in the future could be a function that would receive the request and return the headers.
                  authorization: req.headers[ 'authorization' ]
                }
              }
            }
          }
        }
        opts = Hoek.applyToDefaults(optsWithAuthHeader, opts || {}, true)
      }

      return rbac
        .authorize(id, type, permissions, opts)
        .then((_) => next())
        .catch((_) => {
          next(Boom.unauthorized('Permission denied.' + _)) // Forward the error. Devs should have error handling middleware in place.
        })
    }
  }
}

module.exports = Express
