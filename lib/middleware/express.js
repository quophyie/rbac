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
   * the given permissions. Parameters are the same as rbac.authorize, except for the `id` parameter which can be setup
   * in the constructor options via the getReqId callback.
   * @param {string} permission - The permission to be checked against the principal.
   * @returns {function} - An express middleware signature function.
   */
  authorize (permission) {
    return (req, res, next) => {
      // Get Principal ID from request
      const id = this._rbac._opts.getReqId(req)

      this
        ._rbac
        .authorize(id, { permissions: [ permission ] })
        .then(() => {
          // Sets permission in request object, might be handy
          req.rbac = {
            permission: [ permission ]
          }

          next()
        })
        .catch((err) => {
          // Forwards the error. Devs should have error handling middleware in place.
          next(Boom.unauthorized(err.message))
        })
    }
  }

  /**
   * Global express middleware that checks permissions for all check types
   * @param {string|array} permissions - A permission string or an array of permissions strings
   * @param {string|null} checkType - Permission check type: Default "null". Accepted: "null", "OR", "AND"
   * @returns {function()} - An express middleware signature function.
   * @private
   */
  _authorizeMiddleware (permissions, checkType = null) {
    return (req, res, next) => {
      const headers = {
        authorization: req.headers['authorization']
      }

      return Promise
        .all([])
        .then(() => (!checkType) ? this._rbac.authorizeRemote(permissions, headers) : null)
        .then(() => (checkType === 'OR') ? this._rbac.authorizeRemoteOr(permissions, headers) : null)
        .then(() => (checkType === 'AND') ? this._rbac.authorizeRemoteAnd(permissions, headers) : null)

        .then((body) => {
          if (typeof body === 'object') {
            // Extends req.user with the response
            req.user = req.user || {}
            Hoek.merge(req.user, body)
          }

          next()
        })
        .catch(err => next(Boom.unauthorized(err.message)))
    }
  }

  /**
   * Returns an express middleware function for checking if the principal who made the request is authorized for any of
   * the given permissions. Parameters are the same as rbac.authorizeRemote, except for the `headers` parameter which
   * can be setup in the constructor options via the `remoteAuth.headers` callback. It will define the `authorization`
   * header as the current request authorization header.
   * @param {string} permission - The permission to be checked against the principal.
   * @returns {function} - An express middleware signature function.
   */
  authorizeRemote (permission) {
    return this._authorizeMiddleware(permission)
  }

  /**
   * Express middleware function for "OR" permissions check type
   * @param {array} permissions - An array o permissions to check agains
   * @returns {function} - An express middleware signature function.
   */
  authorizeRemoteOr (permissions) {
    return this._authorizeMiddleware(permissions, 'OR')
  }

  /**
   * Express middleware function for "AND" permissions check type
   * @param {array} permissions - An array o permissions to check agains
   * @returns {function} - An express middleware signature function.
   */
  authorizeRemoteAnd (permissions) {
    return this._authorizeMiddleware(permissions, 'AND')
  }
}

module.exports = Express
