import mongoose = require('mongoose');
import Schema = mongoose.Schema;
import resource = require('../../../src/resource');
import Resource = resource.Resource;

var parentResource = new Resource({
  name: 'parent',
  model: {
    name: String,
    subs: [{
      name: String
    }]
  }
});

export = parentResource;