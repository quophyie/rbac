'use strict'

/**
 * Created by dman on 11/04/16.
 */
var I = require('methodical')
var _ = require('lodash')
var usersInterface = new I(
  {
    required: {
      // Returns user in the system using the user id. Function implementation must take the user's id as the only param. Function must return a bluebird promise
      findUserById: I.function,
       // Returns user's roles using the user id. Function implementation must take the user's id as the only param. Function must return a bluebird promise
      getUserRolesByUserId: I.function
    }
  })

/**
 * An instance of users DAL which takes an implementation of the users DAL interface
 * @param usersDalImplementation: an implementation of the users DAL  interface
 */
function UsersDal (usersDalImplementation) {
  // Will throw an exception if the roles interface above is not  implemented
  usersInterface.check(usersDalImplementation)
  if (this.prototype) {
    this.prototype = _.assign(this.prototype, usersDalImplementation)
  } else {
    _.assign(this, usersDalImplementation)
  }
}

module.exports = UsersDal
