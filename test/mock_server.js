'use strict'

var Express = require('express')
var bodyParser = require('body-parser')

function createServer (port) {
  var server = new Express()
  server.use(bodyParser.json())
  return server
}

module.exports = createServer
