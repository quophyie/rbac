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
   * Returns an express middleware function for checking if a given user is authorized for a given permission.
   * @param {string} permissions - The permission to be checked against the user.
   * @param {object} [localOpts] - Optional options to be passed to the function. Same properties as the constructor.
   * @returns {function} - An express middleware signature function.
   */
  authorize (permissions) {
    return (req, res, next) => {
      // Get userId property in request
      let reqUserId = this._rbac._opts.reqUserId

      this
        ._rbac
        .authorize(this._getDescendantProp(req, reqUserId), permissions)
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

  _getDescendantProp (obj, prop) {
    return prop.split('.').reduce((a, b) => a[b], obj)
  }
}

module.exports = Express
