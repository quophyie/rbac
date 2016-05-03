/* eslint-env mocha */
'use strict'
var Code = require('code')
var expect = Code.expect
var Rbac = require('./../../../lib/index')
var RolesDal = Rbac.Dal.RolesDal // require('./../../../lib/index').Dal.RolesDal
var RolesDalFixture = require('./../fixture/roles_interface_implementation')

describe('RbacBase Tests', function () {
  describe('RbacBase Instance Creation', function () {
    it('Should throw a TypeError exception if rolesDal object passed to RbacBase constructor is not of  type RolesDal ', function (done) {
      var invalidRolesDal = { }
      var constructor = function () {
        let rb = new Rbac.RbacBase(invalidRolesDal)
        rb
      }
      expect(constructor).to.throw(TypeError, 'Parameter "rolesDalImpl" must be of Type "RolesDal"')
      done()
    })

    it('Should create a new RbacBase object when an instance of RolesDal is provided', function (done) {
      var rolesDal = new RolesDal(RolesDalFixture.RolesDalMockImplementation)
      var rbacBase = new Rbac.RbacBase(rolesDal)
      expect(rbacBase).to.be.an.object()
      expect(rbacBase).to.be.an.instanceof(Rbac.RbacBase)
      done()
    })

    /* it('Should throw a TypeError exception if usersDal object passed to RbacBase constructor is not of  type UsersDal', function (done) {
      var constructor = function () {
        let permissionsGroup = 'Test'
        let rolesDal = new RolesDal(RolesDalFixture.RolesDalMockImplementation)
        let rb = new Rbac.RbacBase(rolesDal, {}, permissionsGroup)
        rb
      }
      expect(constructor).to.throw(TypeError, 'Parameter "usersDalImpl" must be of Type "UsersDal"')
      done()
    }) */

    it('Should throw TypeError if permissionGroup param provided is not of type String', function (done) {
      var constructor = function () {
        let permissionsGroup = {}
        let rolesDal = new RolesDal(RolesDalFixture.RolesDalMockImplementation)
        let rb = new Rbac.RbacBase(rolesDal, permissionsGroup)
        rb
      }
      expect(constructor).to.throw(TypeError, 'Parameter "permissionsGroup" must be of Type "String"')
      done()
    })

    it('Should create  a new instance of RbacBase if permissionGroup param of type String', function (done) {
      let permissionsGroup = 'TEST_PERMISSION_GROUP'
      let rolesDal = new RolesDal(RolesDalFixture.RolesDalMockImplementation)
      let rbacBase = new Rbac.RbacBase(rolesDal, permissionsGroup)
      expect(rbacBase).to.be.an.object()
      expect(rbacBase).to.be.an.instanceof(Rbac.RbacBase)
      done()
    })
  })
  describe('RbacBase Functionality', function () {
    let rbacBase = null
    before((done) => {
      let rolesDal = new RolesDal(RolesDalFixture.RolesDalMockImplementation)
      rbacBase = new Rbac.RbacBase(rolesDal)
      rbacBase.initialize().then(() => {
        return rbacBase.getRules()
      }).then((rules) => {
        expect(rules).to.exist().and.to.be.an.object()
      })
        .then(done)
        .catch(done)
    })

    it('Should make sure that getRules returns the rbac rules object', function (done) {
      rbacBase.getRules().then((rules) => {
        let ruleKey = 'DEFAULT:TEST_ROLE_1'
        expect(rules).to.exist().and.to.be.an.object()
        expect(rules[ruleKey]).to.exist().and.to.be.an.object()
        expect(rules[ruleKey].target).to.exist().and.to.be.an.array().and.to.have.length(3)
        expect(rules[ruleKey].target[0]).to.exist().and.to.be.an.object()
        expect(rules[ruleKey].target[0][ruleKey]).to.exist().and.to.equal('update')
        expect(rules[ruleKey].effect).to.exist().and.to.be.a.string().and.to.equal('permit')
      })
        .then(done)
        .catch(done)
    })

    it('Should true when permit is called for a user with the correct permissions', function (done) {
      rbacBase.permit(RolesDalFixture.RoleMembers[0].id,null ,['update']).then((result) => {
        expect(result).to.be.not.null()
        expect(result).to.be.true()
      }).then(done)
        .catch(done)
    })

    it('Should false when permit is called for a user with the correct permissions', function (done) {
      rbacBase.permit(RolesDalFixture.RoleMembers[1].id,null, ['update']).then((result) => {
        expect(result).to.be.not.null()
        expect(result).to.be.false()
      }).then(done)
        .catch(done)
    })

    it('Should false when permit is called for a user without any permissions', function (done) {
      rbacBase.permit(RolesDalFixture.RoleMembers[1].id,null ,[]).then((result) => {
        expect(result).to.be.not.null()
        expect(result).to.be.false()
      }).then(done)
        .catch(done)
    })

    it('Should false when permit is called for a user a null permissions', function (done) {
      rbacBase.permit(RolesDalFixture.RoleMembers[1].id, null).then((result) => {
        expect(result).to.be.not.null()
        expect(result).to.be.false()
      }).then(done)
        .catch(done)
    })

    it('Should true when deny is called for a user with the correct permissions', function (done) {
      rbacBase.deny(RolesDalFixture.RoleMembers[0].id, null, ['update']).then((result) => {
        expect(result).to.be.not.null()
        expect(result).to.be.true()
      }).then(done)
        .catch(done)
    })

    it('Should false when deny is called for a user with the correct permissions', function (done) {
      rbacBase.deny(RolesDalFixture.RoleMembers[1].id, []).then((result) => {
        expect(result).to.be.not.null()
        expect(result).to.be.false()
      }).then(done)
        .catch(done)
    })
  })
})
