'use strict'

const Express = require('./middleware/express')
const Hoek = require('hoek')
const request = require('request-promise')

class Rbac {
  /**
   * Creates a new RBAC instance with the given options.
   * @param {object} opts - Options object.
   * @param {object} [opts.remoteAuth] - Optional configuration object for allowing remote HTTP permission evaluation.
   * @param {object} [opts.remoteAuth.headers] - Optional headers to pass in the HTTP request.
   * @param {string} [opts.remoteAuth.url] - Url for the HTTP request, required if `opts.remoteAuth` is set. The endpoint
   * is expected to accept a JSON object with `user {*}` and `permission {string}` properties and return 200 in case of
   * success or different 200 in case of unauthorized.
   * @param {function} [opts.checkPermission] - Callback function for local permission evaluation with the signature
   * `function (userId, permission)` and returning a Promise. If you're using the Expressjs middleware, `userId` will be the
   * same as `req.user.id` and `permission` the string setup in the middleware. If `opts.remoteAuth` is not set, then this
   * property is required.
   * @param {string} [reqUserId] - the namespace where the userId is setup in the request, for the express middleware.
   */
  constructor (opts) {
    Hoek.assert(typeof opts !== 'undefined', new TypeError('Invalid opts value: must be an object'))
    this._checkOptions(opts)
    this._opts = opts
    this.express = new Express(this)
  }

  /**
   * Checks if a given userId is authorized for a given permission.
   * @param {object|string|number} userId - The user id to be checked for permission.
   * @param {string|array} permission - The permission or permissions to be checked against the user.
   * @param {object} [opts] - Optional options to be passed to the function. Same properties as the constructor.
   * @returns {Promise.<*>} - A promise resolving to the user authorized for the given permission. Depending on the used
   * method (local/remote) and on the callback/HTTP request's response, the promise might have different values.
   */
  authorize (userId, permission, opts) {
    // FIXME turn the whole method into a Promise.
    try {
      // Try to convert userId to Number.
      userId = Number(userId)
      Hoek.assert(!Number.isNaN(userId), new TypeError('Invalid userId value: must be a number'))

      Hoek.assert(typeof permission === 'string' ||
        Array.isArray(permission), new TypeError('Invalid permission value: must be a string or array'))

      if (opts) {
        // First merge with global _opts for setting unset local properties,
        // then check if it's a valid options object
        opts = Hoek.applyToDefaults(this._opts, opts || {}, true)
        this._checkOptions(opts)
      } else {
        opts = this._opts
      }
    } catch (err) {
      return Promise.reject(err)
    }

    if (opts.remoteAuth) {
      return this._checkPermissionRemote(opts.remoteAuth.url, opts.remoteAuth.headers, userId, permission)
    } else {
      // It's a local permission validation, call the callback
      return opts.checkPermission(userId, permission)
    }
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
      // If permission validation is not remote, then must define checkPermission function
      Hoek.assert(typeof opts.checkPermission === 'function', new TypeError('Invalid opts.checkPermission value: must be an function'))
    }
    opts.reqUserId = opts.reqUserId || 'user.id'
  }

  /**
   * Checks for permission over HTTP request.
   * @param {string } url - The URL to be requested.
   * @param {object} headers - Request headers.
   * @param {object|string|number} userId - The user id to be checked for permission.
   * @param {string} permission - The permission to be checked against the user.
   * @returns {Promise.<*>} - A promise resolving to the user authorized for the given permission.
   * @private
   */
  _checkPermissionRemote (url, headers, userId, permission) {
    const opts = {
      uri: url,
      method: 'POST',
      headers: headers,
      json: true,
      body: {
        userId: userId,
        permission: permission
      },
      simple: true // status codes other than 2xx should also reject the promise
    }

    console.log(opts, '---------------------------------------------------------------------')

    return new Promise((resolve, reject) => {
      request(opts)
        .then((res) => {
          console.log('RESULT =============================: ', res)
          resolve(res)
        })
        .catch((err) => {
          console.log('ERROR =============================: ', err)
          reject(err)
        })
    })

  // return request(opts)
  }
}

module.exports = Rbac
