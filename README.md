# RBAC
A reusable package for permission based authorization with local or remote checks and express middleware.

## Install
```
npm install --save @c8/rbac
```

## Usage
Check the `/examples` folder.

## API
### const rbac = new Rbac(opts)
Creates a new Rbac instance with the given options for local or remote authorization. It also provides an express middleware that can use information in the request (i.e. the authentication token or principal) in the authorization process.

```js
const rbac = new Rbac({
  remoteAuth: {
    url: 'http://www.example.com/authorize'
  }
})

app.get('/',
  rbac.express.authorizeRemote(['users:read']),
  (req, res, next) => {
    res.json({ message: 'You have acces to this awesome content!' })
  })
```

* **`opts` {object}** - Options object.
  * **`remoteAuth` {object} (Optional)** - Optional configuration object for allowing remote HTTP permission evaluation.
    *  **`headers` {object} (Optional)** - Optional headers to pass in the HTTP request.
    * **`url` {string}** - Url for the HTTP request, required if `opts.remoteAuth` is set. The endpoint is expected to accept a JSON object with `permissions {array}` property and return 200 in case of success or different 200 in case of unauthorized. It can also return some claims about the principal (i.e. the user id) which will be merged with `req.user`, when called by the express middleware.
  *  **`checkPermission` {function}** - Callback function for local permission evaluation with the signature `(id, permissions)` and returning a Promise. **If `remoteAuth` is not set, then this property is required**.
   * **`getReqId` {function} (Optional)** - A callback with the signature `(req) => {}` that returns the principal ID from the HTTP request object. Defaults to `(req) => req.user.id`.

### rbac.authorize(id, permissions)
Checks if a given principal is authorized for any of the given permissions. Returns a Promise resolving to the principal being allowed the permission. This function can authorize the principal locally, for which you need to define the `checkPermission` callback in the instance options.
   * **`id` {number}** - The principal id to be checked against the permissions.
   * **`permissions` {array}** - The permissions to be checked against the principal.

### rbac.authorizeRemote(permissions, headers)
Checks if a given principal is authorized for any of the given permissions. Returns a Promise resolving to the principal being allowed the permission. The remote server can also return some claims about the principal, which will be returned in the Promise. This function can authorize the principal remotely, for which you need to define the `remoteAuth` object in the instance options.

* **`permissions` {array}** - The permissions to be checked against the principal.
* **`headers` {object} (Optional)** - Optional headers to pass in the HTTP request.

### rbac.express.authorize(permissions)
 Returns an express middleware function for checking if the principal who made the request is authorized for any of the given permissions. Parameters are the same as rbac.authorize, except for the `id` parameter which can be setup in the constructor options via the getReqId callback.

### rbac.express.authorizeRemote(permissions)
Returns an express middleware function for checking if the principal who made the request is authorized for any of the given permissions. Parameters are the same as rbac.authorizeRemote, except for the `headers` parameter which can be setup in the constructor options via the `remoteAuth.headers` callback. It will define the `authorization` header as the current request authorization header.

## Tests

The following commands are available:
+ `coverage` for running code coverage with Istanbul (it shows the report at the bottom)
+ `standard` for code style checks with Standardjs
+ `test` for running Mocha tests

## Versioning
This module adheres to [semver](http://semver.org/) versioning. That means that given a version number MAJOR.MINOR.PATCH, we increment the:

1. MAJOR version when we make incompatible API changes,
2. MINOR version when we add functionality in a backwards-compatible manner, and
3. PATCH version when we make backwards-compatible bug fixes.

Additional labels for pre-release and build metadata are available as extensions to the MAJOR.MINOR.PATCH format.

## License
The MIT License

Copyright (c) 2016 C8 MANAGEMENT LIMITED