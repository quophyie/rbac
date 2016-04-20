'use strict'

/**
 * Created by dman on 11/04/16.
 */
var I = require('methodical')
var _ = require('lodash')
var usersInterface = new I(
  {
    required: {
      findUserById: I.function,
      getUserRolesByUserId: I.function
    }
  })

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
