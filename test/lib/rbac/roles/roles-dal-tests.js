/* eslint-env mocha */
'use strict'

var Code = require('code')
var expect = Code.expect
var RolesDal = require('./../../../../lib/dal/roles/index')
var RolesDalFixture = require('./../../fixture/roles_interface_implementation')

var roles = RolesDalFixture.Roles
var correctlyImplementedInterface = RolesDalFixture.RolesDalMockImplementation
describe('Roles DAL Tests', function () {
  describe('Roles DAL Creation', function () {
    it('Should throw exception if Roles Dal interface is not implemented', function (done) {
      var constructor = function () {
        var rolesDalInstanceWithIncorrectImpl = {
          find: function () {},
          findAllRoles: function () {}
        }
        let rolesDal = new RolesDal(rolesDalInstanceWithIncorrectImpl)
        rolesDal
      }
      expect(constructor).to.throw(TypeError, 'The object does not conform to the interface: ' +
        'The required method "findById" is not implemented; ' +
        'The required method "findByName" is not implemented; ' +
        'The required method "getRoleName" is not implemented; ' +
        'The required method "getRoleId" is not implemented; ' +
        'The required method "getRolePermissionsByRoleName" is not implemented; ' +
        'The required method "getRolePermissionsByRoleId" is not implemented; ' +
        'The required method "findRolesByPermission" is not implemented; ' +
        'The required method "getPermissionName" is not implemented; ' +
        'The required method "getPermissionId" is not implemented')
      done()
    })
    'Parameter "permissionsGroup" must be of Type "String"'
    it('Should return a new instance of the Roles DAL which conforms to the Roles DAL interface', function (done) {
      var rolesDal = new RolesDal(correctlyImplementedInterface)
      expect(rolesDal).to.be.an.object()
      expect(rolesDal.findById).to.be.a.function()
      expect(rolesDal.findByName).to.be.a.function()
      expect(rolesDal.findById).to.be.equal(correctlyImplementedInterface.findById)
      expect(rolesDal.findByName).to.be.a.equal(correctlyImplementedInterface.findByName)
      done()
    })
  })
  describe('Roles DAL Functionality', function () {
    var rolesDal = new RolesDal(correctlyImplementedInterface)
    it('Should return role specified by id when findById is called ', function (done) {
      rolesDal.findById(1).then(function (role) {
        expect(role).to.be.an.object()
        expect(role).to.equal(roles[0])
      })
        .then(done)
        .catch(done)
    })

    it('Should return role specified by name when findByName is called ', function (done) {
      rolesDal.findByName('TEST_ROLE_2').then(function (role) {
        expect(role).to.be.an.object()
        expect(role).to.equal(roles[1])
      })
        .then(done)
        .catch(done)
    })

    it('Should return role permissions when getRolePermissionsByRoleId is called with role id', function (done) {
      rolesDal.getRolePermissionsByRoleId(1).then(function (permissions) {
        expect(permissions).to.be.an.array()
        expect(permissions).to.include(roles[0].permissions)
      })
        .then(done)
        .catch(done)
    })

    it('Should return role permissions when getRolePermissionsByRoleName is called with role name', function (done) {
      rolesDal.getRolePermissionsByRoleName('TEST_ROLE_2').then(function (permissions) {
        expect(permissions).to.be.an.array()
        expect(permissions).to.include(roles[1].permissions)
      })
        .then(done)
        .catch(done)
    })

    it('Should return an array of roles based on the given permission', function (done) {
      rolesDal.findRolesByPermission('read').then(function (permissions) {
        expect(permissions).to.be.an.array()
        expect(permissions).to.not.include(roles[0])
        expect(permissions).to.include(roles[1])
        expect(permissions).to.include(roles[2])
      })
        .then(done)
        .catch(done)
    })

    it('Should return all roles as an array', function (done) {
      rolesDal.findAllRoles().then(function (allRoles) {
        expect(allRoles).to.be.an.array()
        expect(allRoles).to.equal(roles)
      })
        .then(done)
        .catch(done)
    })

    it('Should return role name of given role', function (done) {
      rolesDal.getRoleName(RolesDalFixture.Roles[0]).then(function (role) {
        expect(role).to.be.an.string()
        expect(role).to.equal('TEST_ROLE_1')
      })
        .then(done)
        .catch(done)
    })

    it('Should return roles id of given role', function (done) {
      rolesDal.getRoleId(RolesDalFixture.Roles[0]).then(function (role) {
        expect(role).to.be.a.number()
        expect(role).to.equal(1)
      })
        .then(done)
        .catch(done)
    })

    it('Should return permission name of given permission', function (done) {
      rolesDal.getPermissionName(RolesDalFixture.Roles[0].permissions[0]).then(function (permissionName) {
        expect(permissionName).to.be.a.string()
        expect(permissionName).to.equal('update')
      })
        .then(done)
        .catch(done)
    })

    it('Should return permission id of given permission', function (done) {
      rolesDal.getPermissionId(RolesDalFixture.Roles[0].permissions[0]).then(function (permissionId) {
        expect(permissionId).to.be.a.number()
        expect(permissionId).to.equal(1)
      })
        .then(done)
        .catch(done)
    })
  })
})
