'use strict';

const assert = require('assert');
const traverse = require('traverse');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const { decode } = require('he');
const { merge } = require('lodash');
const debug = require('debug')('mongoose-dompurify');
const caja = require('js-html-sanitizer');

const window = (new JSDOM('')).window;
const sanitizer = createDOMPurify(window);

const defaults = {
  skip: ['_id', 'createdAt', 'updatedAt'],
  encodeHtmlEntities: false,
  iterations: 10,
  sanitizer: {
    SAFE_FOR_JQUERY: true,
    SAFE_FOR_TEMPLATES: true,
    ALLOWED_TAGS: []
  }
};

const filterPhp = (str) => {
  const i = str.indexOf('<?');
  if (i > -1) {
    return str.substring(0, i);
  } else {
    return str;
  }
};

module.exports = exports = function sanitizerPlugin (schema, options = {}) {
  const config = merge({}, defaults, options);

  assert.ok(Array.isArray(config.skip), '\'skip\' must be an array');

  debug('registering plugin on schema with options', config);

  const sanitize = (val) => caja.sanitize(sanitizer.sanitize(filterPhp(val), config.sanitizer));

  schema.pre('save', function (next) {
    const model = this;

    const doc = JSON.parse(JSON.stringify(this.toJSON()));

    debug('running pre:save hook', doc);

    // Sanitize every node in tree
    traverse(doc).map(function (node) {
      const path = this.path.join('.');
      debug('checking', path);

      if (typeof node === 'string' && config.skip.indexOf(path) === -1) {
        let sanitizedNode = sanitize(node);
        if (!config.encodeHtmlEntities) {
          sanitizedNode = decode(sanitizedNode);
        }

        for (var i = 1; i < config.iterations; i++) {
          let previous = sanitizedNode;

          sanitizedNode = sanitize(sanitizedNode);
          if (!config.encodeHtmlEntities) {
            sanitizedNode = decode(sanitizedNode);
          }

          if (sanitizedNode === previous) {
            break;
          }

          debug('iteration', i + 1);
        }

        if (sanitizedNode !== node) {
          model.set(path, sanitizedNode);
          debug(`Sanitized ${path} from "${node}" to "${sanitizedNode}"`);
        }
      }
    });

    next();
  });
};
