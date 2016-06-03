'use strict'

const Express = require('./middleware/express')
const Hoek = require('hoek')
const request = require('request-promise')

class Rbac {
  /**
   * Creates a new Rbac instance with the given options for local or remote authorization. It also provides an express
   * middleware that can use information in the request (i.e. the authentication token or principal) in the authorization
   * process.
   *
   * ```js
   * const rbac = new Rbac({
   *   remoteAuth: {
   *     url: 'http://www.example.com/authorize'
   *   }
   * })
   *
   * app.get('/',
   * rbac.express.authorizeRemote(['users:read']),
   *   (req, res, next) => {
   *     res.json({ message: 'You have acces to this awesome content!' })
   * })
   * ```
   *
   * @param {object} opts - Options object.
   * @param {object} [opts.remoteAuth] - Optional configuration object for allowing remote HTTP permission evaluation.
   * @param {object} [opts.remoteAuth.headers] - Optional headers to pass in the HTTP request.
   * @param {string} [opts.remoteAuth.url] - Url for the HTTP request, required if `opts.remoteAuth` is set. The endpoint
   * is expected to accept a JSON object with `permissions {array}` property and return 200 in case of
   * success or different 200 in case of unauthorized. It can also return some claims about the principal (i.e. the user
   * id) which will be merged with `req.user`, when called by the express middleware.
   * @param {function} [opts.getPermission] - Callback function for local permission evaluation with the signature
   * `function (id)` and returning a Promise resolving to the principal permissions array. **If `opts.remoteAuth` is not
   * set, then this property is required.**
   * @param {function} [getReqId] - A callback with the signature `(req) => {}` that returns the principal ID from the
   * HTTP request object. Defaults to `(req) => req.user.id`
   */
  constructor (opts) {
    Hoek.assert(typeof opts !== 'undefined', new TypeError('Invalid opts value: must be an object'))
    this._checkOptions(opts)
    this._opts = opts
    this.express = new Express(this)
  }

  /**
   * Checks if a given principal is authorized for any of the given permissions. Returns a Promise resolving to the
   * principal being allowed the permission. This function can authorize the principal locally, for which you need to
   * define the `getPermission` callback in the instance options.
   * @param {number} id - The principal id to be checked against the permissions.
   * @param {array} permission - The permissions to be checked against the principal.
   * @returns {Promise.<*>} - A promise resolving to the principal being authorized for a specific permission.
   */
  authorize (id, permissions) {
    return new Promise((resolve, reject) => {
      try {
        // Try to convert userId to Number.
        id = Number(id)
        Hoek.assert(!Number.isNaN(id), new TypeError('Invalid userId value: must be a number.'))

        Hoek.assert(Array.isArray(permissions), new TypeError('Invalid permissions value: must be a string or array.'))
      } catch (err) {
        return reject(err)
      }

      if (!this._opts.getPermission) {
        return reject(new Error('Local authorization not configured.'))
      }

      return this
        ._opts
        .getPermission(id)
        .then((principalPermissions) => {
          // Compare permissions
          const foundPermission = Hoek.intersect(permissions, principalPermissions, true)
          if (foundPermission) {
            return resolve(foundPermission) // Return the first intersected permission
          } else {
            return reject(new Error('Permission denied.'))
          }
        })
        .catch(reject)
    })
  }

  /**
   * Checks if a given principal is authorized for any of the given permissions. Returns a Promise resolving to the
   * principal being allowed the permission. The remote server can also return some claims about the principal, which
   * will be returned in the Promise. This function can authorize the principal remotely, for which you need to define
   * the `remoteAuth` object in the instance options.
   * @param {array} permissions - The permissions to be checked against the principal.
   * @param {object} [headers] - Optional headers to pass in the HTTP request.
   * @returns {Promise.<*>} - A promise resolving to the principal being authorized for the given permissions.
   */
  authorizeRemote (permissions, headers) {
    return new Promise((resolve, reject) => {
      try {
        Hoek.assert(Array.isArray(permissions), new TypeError('Invalid permissions value: must be a string or array.'))
      } catch (err) {
        return reject(err)
      }

      if (!this._opts.remoteAuth) {
        return reject(new Error('Remote authorization not configured.'))
      }

      // Merge headers with opts
      headers = headers || {}
      const mergedHeaders = Hoek.applyToDefaults(this._opts.remoteAuth.headers, headers, true)

      return this
        ._authorizeRemote(permissions, mergedHeaders)
        .then(resolve)
        .catch(reject)
    })
  }

  /**
   * Checks option constraints and set defaults.
   * @param opts
   * @private
   */
  _checkOptions (opts) {
    if (typeof opts.remoteAuth === 'object') {
      opts.remoteAuth.headers = opts.remoteAuth.headers || {}
      Hoek.assert(typeof opts.remoteAuth.url === 'string', new TypeError('Invalid opts.remoteAuth.url value: must be an string'))
    } else {
      // If permission validation is not remote, then must define getPermission function
      Hoek.assert(typeof opts.getPermission === 'function', new TypeError('Invalid opts.getPermission value: must be an function'))
    }

    // Set default getReqId
    opts.getReqId = opts.getReqId || ((req) => req.user.id)
  }

  /**
   * Checks for permissions over HTTP request.
   * @param {array} permissions - The permissions to be checked against the principal.
   * @param {object} [headers] - Extra headers to be passed along in the request.
   * @returns {Promise.<*>} - A promise resolving to the principal being authorized for the given permissions.
   * @private
   */
  _authorizeRemote (permissions, headers) {
    const opts = {
      uri: this._opts.remoteAuth.url,
      method: 'POST',
      headers: headers,
      json: true,
      body: {
        permissions: permissions
      },
      simple: true  // status codes other than 2xx should also reject the promise
    }
    return request(opts)
  }
}

module.exports = Rbac
