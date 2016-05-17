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
   * @param {string} permission - The permission to be checked against the user.
   * @param {object} [opts] - Optional options to be passed to the function. Same properties as the constructor.
   * @returns {function} - An express middleware signature function.
   */
  authorize (permission, opts) {
    const self = this
    return function (req, res, next) {
      if (self._rbac._opts.remoteAuth ||
        (opts && typeof opts.remoteAuth === 'object')) {
        // If options are set for remote authorization, setup the authorization header.
        const optsWithAuthHeader = {
          remoteAuth: {
            headers: {
              // Forwards the authorization header.
              // FIXME in the future could be a function that would receive the request and return the headers.
              authorization: req.headers[ 'authorization' ]
            }
          }
        }
        opts = Hoek.applyToDefaults(opts || {}, optsWithAuthHeader, true)
      }

      self
        ._rbac
        .authorize(req.user.id, permission, opts)
        .then((_) => {
          // Sets permission in request object, might be handy
          req.rbac = {
            permission: permission
          }

          next()
        })
        .catch((_) => {
          next(Boom.unauthorized('Permission denied.')) // Forward the error. Devs should have error handling middleware in place.
        })
    }
  }
}

module.exports = Express
