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
 * **`opts` (Required)** -  is an object literal containing options to control how the permissions are being verified (locally or remotely);
   * **`remoteAuth`** - An object specifying how to check the user with the given permissions against a remote server;
     * **`url` (Required)** - If `remoteAuth` is set, then you must specify the url of the remote server;
     * **`headers`** - An object containing headers passed with the remote server's request;
   * **`checkPermission`** - Callback function for local permission evaluation with the signature `function (userId, permission)` and returning a Promise. If you're using the Expressjs middleware, `userId` will be the same as `req.user.id` and `permission` the string or array setup in the middleware. If `opts.remoteAuth` is not set, then this property is **required**.
   * **`reqUserId`** - the namespace where the userId is setup in the request, for the express middleware. Defaults to `'user.id'`.

### rbac.authorize(userId, permission, opts)
   Checks if a given user is authorized for a given permission. Returns a Promise resolving to the user being allowed the
   permission. This function can authorize the user both locally or remotely. For that you need to implement the `checkPermission`
   callback or `remoteAuth.url`, respectively. Although it can make authorize from two different sources, the flow
   is the same.
   * **`userId` (Required)** - The ID of user to be checked for permission.
   * **`permission` (Required)** - The permission or permissions to be checked against the user.
   * **`opts`** - Optional options to be passed to the function. Same properties as the constructor.

### rbac.express.authorize(permission, opts)
 Returns an express middleware function for checking if a given user is authorized for a given permission.
 Parameters are the same as `rbac.authorize`, except for the `userId` parameter which can be setup in the constructor. Note
 that this middleware also sets the authorization header with the current request's header, for remote authorization. If you
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
