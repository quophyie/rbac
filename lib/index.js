'use strict'

const Express = require('./middleware/express')
const Hoek = require('hoek')
const request = require('request-promise')

class Rbac {
  /**
   * Creates a new Rbac instance with the given options.
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
   * Checks if a given userId is authorized for a given permission.
   * @param {object|string|number} id - The user id to be checked for permission.
   * @param {string|array} permission - The permission or permissions to be checked against the user.
   * @param {object} [opts] - Optional options to be passed to the function. Same properties as the constructor.
   * @returns {Promise.<*>} - A promise resolving to the user authorized for the given permission. Depending on the used
   * method (local/remote) and on the callback/HTTP request's response, the promise might have different values.
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

      if (!this._opts.checkPermission) {
        return reject(new Error('Local authorization not configured.'))
      }

      return this
        ._opts
        .checkPermission(id, permissions)
        .then(resolve)
        .catch(reject)
    })
  }

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

      return this
        ._authorizeRemote(permissions, headers)
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
      // If permission validation is not remote, then must define checkPermission function
      Hoek.assert(typeof opts.checkPermission === 'function', new TypeError('Invalid opts.checkPermission value: must be an function'))
    }

    // Set default getReqId
    opts.getReqId = opts.getReqId || ((req) => req.user.id)
  }

  /**
   * Checks for permissions over HTTP request.
   * @param {string } url - The URL to be requested.
   * @param {object} headers - Request headers.
   * @param {string} permissions - The permissions to be checked against the user.
   * @returns {Promise.<*>} - A promise resolving to the user authorized for the given permissions.
   * @private
   */
  _authorizeRemote (permissions, headers) {
    // Merge headers with opts
    headers = headers || {}
    const mergedHeaders = Hoek.applyToDefaults(this._opts.remoteAuth.headers, headers, true)

    const opts = {
      uri: this._opts.remoteAuth.url,
      method: 'POST',
      headers: mergedHeaders,
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
