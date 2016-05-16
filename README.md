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
   * **`checkPermission`** - Callback function for local permission evaluation with the signature `function (user, permission)` and returning a Promise. If you're using the Expressjs middleware, `user` will be the same as `req.user` and `permission` the string or array setup in the middleware. If `opts.remoteAuth` is not set, then this property is **required**.

### rbac.allow(user, permission, opts)
   Checks if a given user is allowed for a given permission.
   * **`user` (Required)** - The user to be checked for permission.
   * **`permission` (Required)** - The permission or permissions to be checked against the user.
   * **`opts`** - Optional options to be passed to the function. Same properties as the constructor.

### rbac.express.allow(permission, opts)
 Returns an express middleware function for checking if a given user is allowed for a given permission. Parameters are the same as `rbac.allow`, except for the `user` parameter which does not apply here.

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
