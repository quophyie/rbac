# RBAC
A reusable package for role based access (authorization). This package user defines the roles, permissions and a role members store / db. This package will simple plugs into roles, permissions and a role members store / db to effect RBAC. The this module is  agnostic of the underlying data store / db. This means that you can use any database / data store that you want e.g. `Postgres`, `Mongo Db`, `Cassandra` or even a file or simple file system etc. To use the package, you simply implement the defined interfaces and you are ready to go

## Main Components
+ RBACBase (A base implementation of Role-Based Access Control)
+ RbacExpress (An express middleware that uses RBACBase to effect Role-Based Access Control)

## Usage
Check the `/examples` folder.

## API
### RbacExpress

#### RbaceExpress.initialize(opts) - Initialises RbacExpress module.

   * opts - Options for RbacExpress. It should at the  very least provide an implementation of roles DAL and  UsersDal and Users DAL and optionally a 'defaultAction' property which can have a value of `permit` or `deny`.
   ### NOTE : The `permit` and `deny` methods of RbacExpress require a `user` object on the `req` object with at least the following shape i.e.
```js
   req.user = {
                id:  1, //The user id of the user we want to test permissions for
                target:'SOME_MEMBER_TYE' // The target refers to the memberType e.g. 'USER', 'EXTERNAL_APP', etc
              }
```
   The `opts` object is defined as follows

#### opts
**// RolesDal interface: The primary interface that must be implemented**

#### RolesDal: [required]{
* **findById**: Returns a role using the role id. Function implementation must take a role id as the only param. Function must return a bluebird promise

* **findByName**: Returns a role using the role name. Function implementation must take a role name as the only param. Function must return a bluebird promise

* **getRoleName**: Returns a role's name. Function implementation must take a role instance as the only param. Function must return a bluebird promise
* **getRoleId**: Returns a role id using of the given role. Function implementation must take a role instance as the only param. Function must return a bluebird promise

* getRolePermissionsByRoleName: Returns an array permissions of role using a role name. Function implementation must take a role name as the only param. Function must return a bluebird promise
* **getRolePermissionsByRoleId**: Returns an array permissions of role using a role id. Function implementation must take a role id as the only param. Function must return a bluebird promise,
* **findRolesByPermission**: Returns an array roles of of a given permission. Function implementation must take an instance of a permission as the only param. Function must return a bluebird promise,
* **getPermissionName**: Returns a given permission's name. Function implementation must take an instance of a permission as the only param. Function must return a bluebird promise
* **getPermissionId**: Returns a given permission's id. Function implementation must take an instance of a permission as the only param. Function must return a bluebird promise,

* **findAllRoles**: Returns all roles in  the system. The function does not take any params. Function must return a bluebird promise
* **findMemberRoles**: Returns a role member's roles using the member id and an optional member type (e.g. Member Types i.e. 'USER', 'EXTERNAL_APPLICATION', etc). Member types are used to discriminate between the different groups / types in the role member data store /db. For example if you have an external user role members store /db  and an internal user's role members store / db, you can use the `memberType` param to tell the function how to retrieve roles for internal members and external members and hence to possibly call different retrieval services for the the different types of members. Function implementation must take the member's id and an optional member type
   #### },
The default action to perform if a user's does not have a specified permision. Can be one of `permit` or `deny`
#### defaultAction : default 'deny' [optional].
* An instance of the express app
#### app: app [optional]
#### }

### RbaceExpress.allow(permissions, permissionsGroup) -  
  Allows access to the next middleware if the user has one of the permissions in the permissions array

   + **@param permissions**: an array of permissions which allow  access to the next middleware
   + **@param permissionsGroup**: [optional] The permission group to which the array of permissions belong (for e.g. `Credentials`, `UsersAccess` etc). If you are unsure, then dont provide this parameter,in which case the permission will added to the **`'DEFAULT'`** permissions group
   + @returns express middleware

### RbaceExpress.deny(permissions, permissionsGroup) -  
   Denies access to the next middleware if the user has one of the permissions in the permissions array (i.e. the next middleware is **not** called)

  + **@param {array} permissions**: an array of permissions which allow  access to the next middleware
  + **@param permissionsGroup**: [optional] The permission group to which the array of permissions belong (for e.g. `Credentials`, `UsersAccess` etc). If you are unsure, then dont provide this parameter,in which case the permission will added to the **`'DEFAULT'`** permissions group
  + **@returns** express middleware

# RbacBase
### Use RbacBase if you just want the RBAC functionality without the express wrapper. This is a base implentation of Rbac System. This class drives the rbac system

## contructor

 + **@param {RolesDal}  rolesDalImpl** -  An implentation of the RolesDal interface
 + **@param {UsersDal} usersDalImpl** - An implentation of the UsersDal interface
 + **@param {string} permsGroup** - The permissionGroup that RbacBase must work on. It allows callers to define different groups of permissions. For example 'Credentials' group, 'UserAccess' group. If not
 the RbacBase will assume the 'DEFAULT' permission group.

 *** NOTE *** If permGroup is provided, then same permissionGroup must be provided when `permit` and `deny`  methods are called
 + **@param {boolean} conjuncti**on - a boolean that specifies how permissions must be evaluated. If `true`, then permissions array in params list of `permit` or `deny`  methods must match
  all the permissions on a given role in order to be evaulated as true. If `false`,then permissions array in params list of `permit` or `deny`  methods must match
  one of the permissions on a given role in order to be evaulated as true. For example, if a role is defined as


```js
role  = {
            id: 1,
            name: 'RoleA',
            permissions: ['update','read']
           }
```
  If `@conjunction = true`, then permissions array in params list of `permit` or `deny`  methods must be ['update','read'] in order to evaluate to true, If however, @conjunction = false,
  then permissions array in params list of `permit` or `deny`  methods cab be on of ['update','read'] , ['update'] or ['read']  in order to evaluate to true.
  The default value is false

# Example

## RolesDal Mock Implementation
file roles_interface_implementation.js
```js
'use strict'
var _ = require('lodash')
var Promise = require('bluebird')
const roles = [
  {
    id: 1,
    roleName: 'TEST_ROLE_1',
    permissions: [
      {
        id: 1,
        name: 'update'
      },
      {
        id: 6,
        name: 'delete'
      }
    ]
  },
  {
    id: 2,
    roleName: 'TEST_ROLE_2',
    permissions: [
      {
        id: 2,
        name: 'read'
      },
      {
        id: 4,
        name: 'write'
      }]
  },
  {
    id: 3,
    roleName: 'TEST_ROLE_3',
    permissions: [
      {
        id: 5,
        name: 'read'
      }
    ]
  },
  {
    id: 4,
    roleName: 'TEST_ROLE_1',
    permissions: [
      {
        id: 1,
        name: 'update'
      }
    ]
  }, {
    id: 5,
    roleName: 'TEST_ROLE_1',
    permissions: [
      {
        id: 2,
        name: 'read'
      }
    ]
  }
]


let roleMembers = [
  {
    id: 1,
    email: 'superman@c8management.com',
    roles: [roles[0], roles[2]]
  },
  {
    id: 2,
    email: 'batman@c8management.com',
    roles: [roles[2]]
  }
]

module.exports = {
  Roles: roles,
  RolesDalMockImplementation: {
    findById: function (id) {
      return Promise.resolve(_.find(roles, function (item) {
        return item.id === id
      })
      )
    },
    findByName: function (name) {
      return Promise.resolve(_.find(roles, function (item) {
        return item.roleName === name
      })
      )
    },
    getRolePermissionsByRoleName: function (name) {
      let permissions = []
      let _roles = []

      _roles = _.filter(roles, function (item) {
        return item.roleName === name
      })
      permissions = _.map(_roles, (role) => {
        if (role && role.permissions) {
          return role.permissions
        }
      })
      permissions = _.flatMap(permissions, (perm) => {
        return perm
      })
      return Promise.resolve(permissions)
    },
    getRolePermissionsByRoleId: function (id) {
      let role = _.find(roles, function (item) {
        return item.id === id
      })
      return Promise.resolve(role.permissions)
    },
    findRolesByPermission: function (permission) {
      let foundRoles = []
      _.forEach(roles, function (role) {
        let filtered = _.filter(role.permissions, function (role_permission) {
          return role_permission.name === permission
        })
        if (filtered && filtered.length > 0) {
          foundRoles.push(role)
        }
      })

      return Promise.resolve(foundRoles)
    },
    findAllRoles: function () {
      return Promise.resolve(roles)
    },
    getRoleName: function (role) {
      return Promise.resolve(role.roleName)
    },
    getRoleId: function (role) {
      return Promise.resolve(role.id)
    },
    getPermissionName: function (permission) {
      return Promise.resolve(permission.name)
    },
    getPermissionId: function (permission) {
      return Promise.resolve(permission.id)
    },
     // Returns a role member's roles using the member id. Function implementation must take the member's id and an optional member type (e.g. Member Types i.e. 'USER', 'EXTERNAL_APPLICATION', etc) as the only params. Function must return a bluebird promise
    findMemberRolesByMemberId: function (memberId, memberType) {
       return Promise.resolve(memberRoles)
    },

  }
}
```

## RbacExpress Usage
```js
const app = require('express')
const rbacExpress = require('@c8/rbac').Express
const rolesDalMock = require('./roles_interface_implementation')
const usersDalMock = require('./user_dal_interface_implementation')
let opts = {
  RolesDal: rolesDalMock,
  UsersDal: usersDalMock,
  app: app
}

server.use(rbacExpress.initialize(opts))
server.user((req, res, next) => {
  //Set the user  on the req object
  req.user = {
               id:  1
             }
})

//Allow users that have the update permission
server.get('/some-rbac', rbacExpress.allow(['update']), (req, res) => {
  res.send({ response: 'some authorized content' })
})

// The response below will not be sent (i.e the next middleware) will  be called because the rbacExpress does not know about the permission `some_unkown_permision`
server.get('/some-unauthorized-rbac', rbacExpress.allow(['some_unkown_permision']), (req, res) => {
  res.send({ response: 'some other unknwn authorized content' })
})

// The users with the permission `standard_user` will be denied access to the resource i.e The client will recieve an error response i.e **`{ "error_code": 1100,"error": "Permission to resource }`**

server.get('/rbacExpress', auth.express.authenticate(), rbacExpress.deny(['standard_user']), (req, res) => {
  res.send({ response: 'some denied authorized content' })
})
// The response below will be an error response (i.e **`{ "error_code": 1100,"error": "Permission to resource }`**) because the route \ url does not have an rbac operation attached to it
server.get('/some-unreachable', auth.express.authenticate(), (req, res) => {
  res.send({ response: 'this url should be unreachable as there are no permissions set on the route' })
})
server.listen(9000, () => {
  console.log('Listening on http://localhost:9000')
})
```
### RbacBase Usage
```js
  const app = require('express')
  const rbacBase = require('@c8/rbac').RbacBase
  const rolesDalMock = require('./roles_interface_implementation')
  const usersDalMock = require('./user_dal_interface_implementation')
  rbacBase = new Rbac.RbacBase(rolesDalMock, usersDalMock)
  // initialise RbacBase
     rbacBase.initialize()
     .then(() => {
       return rbacBase.getRules()
     }).then((rules) => {
        // Do something with the rules
     })

     rbacBase.permit(1, ['update']).then((result) => {
       //Do something if the user is  allowed / permitted
     })
    .catch(() => {
      //handle error
     })
   })

   rbacBase.deny(1, ['delele']).then((result) => {
     //Do something if the user is  denied permission
   })
  .catch(() => {
       //handle error
  })
 })
```   
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
