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
   * @param {array} permissions - The permission to be checked against the principal.
   * @returns {function} - An express middleware signature function.
   */
  authorize (permissions) {
    return (req, res, next) => {
      // Get Principal ID from request
      const id = this._rbac._opts.getReqId(req)

      this
        ._rbac
        .authorize(id, permissions)
        .then(() => {
          // Sets permission in request object, might be handy
          req.rbac = {
            permission: permissions
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
   * Returns an express middleware function for checking if the principal who made the request is authorized for any of
   * the given permissions. Parameters are the same as rbac.authorizeRemote, except for the `headers` parameter which
   * can be setup in the constructor options via the `remoteAuth.headers` callback. It will define the `authorization`
   * header as the current request authorization header.
   * @param {array} permissions - The permission to be checked against the principal.
   * @returns {function} - An express middleware signature function.
   */
  authorizeRemote (permissions) {
    return (req, res, next) => {
      const headers = {
        authorization: req.headers['authorization']
      }

      this
        ._rbac
        .authorizeRemote(permissions, headers)
        .then((body) => {
          if (typeof body === 'object') {
            // Extends req.user with the response
            req.user = req.user || {}
            Hoek.merge(req.user, body)
          }

          next()
        })
        .catch((err) => {
          next(Boom.unauthorized(err.message))
        })
    }
  }
}

module.exports = Express
