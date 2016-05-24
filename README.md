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
Creates a new Rbac instance with the given options. `opts.principal` object can specify options for different types of principals, for instance, when you'd need to authorize different principals against different endpoints:
```js
const rbac = new Rbac({
  principals: {
    users: {
      remoteAuth: {
        url: 'http://www.example.com/users/authorize'
      }
    },
    apps: {
      remoteAuth: {
        url: 'http://www.example.com/apps/authorize'
      }
    }
  }
})
```

* **`opts` {object}** - Options object.
  *  **`principals` {object}** - The available principals configurations. Each principal is an object inside `opts.principals` with the key equal to the principal name (i.e. users, apps, etc.) with the given properties:
     * **`remoteAuth` {object} (Optional)** - Optional configuration object for allowing remote HTTP permission evaluation.
       *  **`headers` {object} (Optional)** - Optional headers to pass in the HTTP request.
       * **`url` {string}** - Url for the HTTP request, required if `opts.remoteAuth` is set. The endpoint is expected to accept a JSON object with `id` {number} and `permission` {array} properties and return 200 in case of success or different 200 in case of unauthorized.
     *  **`checkPermission` {function}** - Callback function for local permission evaluation with the signature `(id, permissions)` and returning a Promise. **If `remoteAuth` is not set, then this property is required**.
   * **`getReqId` {function} (Optional)** - A callback with the signature `(req) => {}` that returns the principal ID from the HTTP request object. Defaults to `(req) => req.user.id`.
   * **`getReqType` {function} (Optional)** - A callback with the signature `(req) => {}` that returns the principal type (i.e. users, apps, etc.) from the HTTP request object. Defaults to `(req) => req.user.type`.

### rbac.authorize(id, permissions, opts)
Checks if a given principal is authorized for any of the given permissions. Returns a Promise resolving to the principal being allowed the permission. This function can authorize the user both locally or remotely. For that you need to implement the `checkPermission` callback or `remoteAuth.url`, respectively. Although it can make authorize from two different sources, the flow is the same.
   * **`id` {number}** - The principal id to be checked against the permissions.
   * **`permissions` {array}** - The permissions to be checked against the principal.
   * **`opts`** - Optional options to be passed to the function. Same properties as the constructor.

### rbac.express.authorize(permissions, opts)
 Returns an express middleware function for checking if the principal who made the request is authorized for any of the given permissions. Parameters are the same as `rbac.authorize`, except for the `userId` parameter which can be setup in the constructor options via the `getReqId` callback. Note that this middleware also sets the authorization header with the current request's header, for remote authorization. If you
 don't want this behaviour, set it to `undefined` in `opts`.

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
