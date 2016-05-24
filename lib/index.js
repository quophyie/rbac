'use strict'

const Express = require('./middleware/express')
const Hoek = require('hoek')
const request = require('request-promise')

class Rbac {
  /**
   * Creates a new Rbac instance with the given options. `opts.principal` object can specify options for different types
   * of principals, for instance, when you'd need to authorize different principals against different endpoints:
   *
   * ```js
   * const rbac = new Rbac({
   *   principals: {
   *     users: {
   *       remoteAuth: {
   *         url: 'http://www.example.com/users/authorize'
   *       }
   *     },
   *     apps: {
   *       remoteAuth: {
   *         url: 'http://www.example.com/apps/authorize'
   *       }
   *     }
   *   }
   * })
   * ```
   *
   * @param {object} opts - Options object.
   * @param {object} principals - The available principals configurations. Each principal is an object inside
   * `opts.principals` with the key equal to the principal name (i.e. users, apps, etc.) with the given properties:
   *   + {object} [remoteAuth] - Optional configuration object for allowing remote HTTP permission evaluation.
   *   + {object} [remoteAuth.headers] - Optional headers to pass in the HTTP request.
   *   + {string} [remoteAuth.url] - Url for the HTTP request, required if `opts.remoteAuth` is set. The endpoint
   * is expected to accept a JSON object with `id` {number} and `permissions` {array} properties and return 200 in case of
   * success or different 200 in case of unauthorized.
   *   + {function} [checkPermission] - Callback function for local permission evaluation with the signature
   * `(id, permissions)` and returning a Promise. **If `remoteAuth` is not set, then this property is required.**
   * @param {function} [getReqId] - A callback with the signature `(req) => {}` that returns the principal ID from the
   * HTTP request object. Defaults to `(req) => req.user.id`
   * @param {function} [getReqType] - A callback with the signature `(req) => {}` that returns the principal type (i.e.
   * users, apps, etc.) from the HTTP request object. Defaults to `(req) => req.user.type`
   */
  constructor (opts) {
    Hoek.assert(typeof opts !== 'undefined', new TypeError('Invalid opts value: must be an object'))
    this._checkOptions(opts)
    this._opts = opts
    this.express = new Express(this)
  }

  /**
   * Checks if a given principal is authorized for any of the given permissions. Returns a Promise resolving to the
   * principal being allowed the permission. This function can authorize the user both locally or remotely. For that you
   * need to implement the `checkPermission` callback or `remoteAuth.url`, respectively. Although it can make authorize
   * from two different sources, the flow is the same.
   * @param {number} id - The principal id to be checked against the permissions.
   * @param {array} permissions - The permissions to be checked against the principal.
   * @param {object} [opts] - Optional options to be passed to the function. Same properties as the constructor.
   * @returns {Promise.<*>} - A promise resolving to the principal being authorized for the given permissions.
   */
  authorize (id, type, permissions, opts) {
    // FIXME turn the whole method into a Promise.
    try {
      // Try to convert id to Number.
      id = Number(id)
      Hoek.assert(!Number.isNaN(id), new TypeError('Invalid id value: must be a number'))

      Hoek.assert(Array.isArray(permissions), new TypeError('Invalid permissions value: must be an array'))

      if (opts) {
        // First merge with global _opts then check if it's a valid options object
        opts = Hoek.applyToDefaults(this._opts, opts || {}, true)
        this._checkOptions(opts)
      } else {
        opts = this._opts
      }
    } catch (err) {
      return Promise.reject(err)
    }

    // Get options for given Principal type
    const principalOpts = opts.principals[type]
    if (!principalOpts) {
      return Promise.reject(new Error('Principal type does not exist'))
    }

    if (principalOpts.remoteAuth) {
      return this._checkPermissionRemote(principalOpts.remoteAuth.url, principalOpts.remoteAuth.headers, id, permissions)
    } else {
      // It's a local permissions validation, call the callback
      return principalOpts.checkPermission(id, permissions)
    }
  }

  /**
   * Checks option constraints and set defaults.
   * @param opts
   * @private
   */
  _checkOptions (opts) {
    if (!opts) {
      return
    }

    Hoek.assert(typeof opts.principals !== 'undefined',
      new TypeError('Invalid opts.principals value: must be an object'))

    const principals = opts.principals
    for (let key in principals) {
      if (principals.hasOwnProperty(key)) {
        // Check options for each principal type
        this._checkTypeOptions(key, principals[key])
      }
    }

    // Set default getReqId and getReqType
    opts.getReqId = opts.getReqId || ((req) => req.user.id)
    opts.getReqType = opts.getReqType || ((req) => req.user.type)
  }

  /**
   * Checks option constraints for a given principal type and set defaults.
   * @param type - The Principal name
   * @param opts
   * @private
   */
  _checkTypeOptions (type, opts) {
    if (typeof opts.remoteAuth === 'object') {
      opts.remoteAuth.headers = opts.remoteAuth.headers || {}
      Hoek.assert(typeof opts.remoteAuth.url === 'string',
        new TypeError(`Invalid ${type}.opts.remoteAuth.url value: must be an string`))
    } else {
      // If permission validation is not remote, then must define checkPermission function
      Hoek.assert(typeof opts.checkPermission === 'function',
        new TypeError(`Invalid ${type}.opts.checkPermission value: must be an function`))
    }
  }

  /**
   * Checks for permission over HTTP request.
   * @param {string } url - The URL to be requested.
   * @param {object} headers - Request headers.
   * @param {number} id - The principal id to be checked for permission.
   * @param {array} permissions - The permissions to check against the principal.
   * @returns {Promise.<*>} - A promise resolving to the principal being authorized for the given permission.
   * @private
   */
  _checkPermissionRemote (url, headers, id, permissions) {
    console.log(url)
    console.log(headers)
    console.log(id)
    console.log(permissions)
    const opts = {
      uri: url,
      method: 'POST',
      headers: headers,
      json: true,
      body: {
        id: id,
        permissions: permissions
      },
      simple: true  // status codes other than 2xx should also reject the promise
    }
    return request(opts)
  }
}

module.exports = Rbac
