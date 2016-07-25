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
   * Checks if a given principal is authorized for any of the given permissions. Returns a Promise resolving to the
   * principal being allowed the permission. This function can authorize the principal locally, for which you need to
   * define the `getPermission` callback in the instance options.
   * @param {number} id - The principal id to be checked against the permissions.
   * @param {object} body - The permission object.
   * @param {array} body.permissions - The permissions to be checked against the principal.
   * @param {string|null} body.checkType - The permissions check type to be applied
   * @returns {Promise.<*>} - A promise resolving to the principal being authorized for a specific permission.
   */
  authorize (id, body) {
    let permissions = body.permissions || Promise.reject(new TypeError('Missing permissions'))
    let checkType = body.checkType || null

    if (!id) return Promise.reject(new TypeError('Requestor Id must be set'))

    if (!Array.isArray(permissions)) {
      return Promise.reject(new TypeError('Invalid permissions value: must be an array'))
    }

    if ((permissions.length > 1 && !checkType) || (permissions.length < 2 && checkType)) {
      return Promise.reject(
        new TypeError(`Invalid permissions:checkType combination. [${permissions}]:${checkType}`))
    }

    if (!this._opts.getPermission) {
      return Promise.reject(new Error('Local authorization not configured.'))
    }

    return this._opts
      .getPermission(id)
      .then((principalPermissions) => {
        const granted = ((type) => {
          switch (type) {
            case null:
              return Hoek.intersect(permissions, principalPermissions).length === permissions.length
            case 'OR':
              return Hoek.contain(permissions, principalPermissions)
            case 'AND':
              return Hoek.deepEqual(permissions, principalPermissions, { prototype: false })
            default:
              return false
          }
        })(checkType)

        return granted || Promise.reject(new Error('Permission denied.'))
      })
  }

  /**
   * Checks if a given principal is authorized for any of the given permissions. Returns a Promise resolving to the
   * principal being allowed the permission. The remote server can also return some claims about the principal, which
   * will be returned in the Promise. This function can authorize the principal remotely, for which you need to define
   * the `remoteAuth` object in the instance options.
   * @param {string} permission - The permission to be checked against the principal.
   * @param {string} auth - Authorization.
   * @returns {Promise.<*>} - A promise resolving to the principal being authorized for the given permissions.
   */
  authorizeRemote (permission, auth) {
    if (typeof permission !== 'string') {
      return Promise.reject(new TypeError('Invalid permissions value: must be a string'))
    }
    return this._authorizeRemote([ permission ], auth)
  }

  /**
   * Checks if a given principal is authorized for any of the given permissions.
   * @param {array} permissions - An array of permissions to check agains
   * @param {string} auth - Authorization.
   * @returns {Promise.<*>}
   */
  authorizeRemoteOr (permissions, auth) {
    if (!Array.isArray(permissions)) {
      return Promise.reject(new TypeError('Invalid permissions value: must be an array'))
    }
    return this._authorizeRemote(permissions, auth, 'or')
  }

  /**
   * Checks if a given principal is authorized for all of the given permissions.
   * @param {array} permissions - An array of permissions to check agains
   * @param {string} auth - Authorization.
   * @returns {Promise.<*>}
   */
  authorizeRemoteAnd (permissions, auth) {
    if (!Array.isArray(permissions)) {
      return Promise.reject(new TypeError('Invalid permissions value: must be an array'))
    }
    return this._authorizeRemote(permissions, auth, 'and')
  }

  /**
   * Checks for permissions over HTTP request.
   * @param {array} permissions - The permissions to be checked against the principal.
   * @param {string} auth - Auth header as string. Ex: Bearer ....
   * @param {string|null} checkType - The check type to compary the permissions against. Either null, "or", "and"
   * @param {object} headers - Additional request headers
   * @returns {Promise.<*>} - A promise resolving to the principal being authorized for the given permissions.
   * @private
   */
  _authorizeRemote (permissions, auth, checkType, headers = {}) {
    if (!this._opts.remoteAuth) {
      return Promise.reject(new Error('Remote authorization not configured.'))
    }

    headers = (auth) ? Object.assign(headers, { authorization: auth }) : headers

    const opts = {
      uri: this._opts.remoteAuth.url,
      method: 'POST',
      headers: Object.assign(this._opts.remoteAuth.headers, headers),
      json: true,
      body: {
        permissions: permissions,
        checkType: checkType || null
      },
      simple: true // status codes other than 2xx should also reject the promise
    }
    return request(opts)
  }
}

module.exports = Rbac
