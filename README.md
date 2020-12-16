# mongoose-dompurify

[![Build Status](https://travis-ci.org/compwright/mongoose-dompurify.svg?branch=master)](https://travis-ci.org/compwright/mongoose-dompurify)
[![Dependency Status](https://img.shields.io/david/compwright/mongoose-dompurify.svg?style=flat-square)](https://david-dm.org/compwright/mongoose-dompurify)
[![Download Status](https://img.shields.io/npm/dm/mongoose-dompurify.svg?style=flat-square)](https://www.npmjs.com/package/mongoose-dompurify)
[![Sponsor on GitHub](https://img.shields.io/static/v1?label=Sponsor&message=❤&logo=GitHub&link=https://github.com/sponsors/compwright)](https://github.com/sponsors/compwright)

[DOMPurify](https://github.com/cure53/DOMPurify) plugin for Mongoose schemas that sanitizes documents before saving.

## Installation

```bash
$ npm install --save mongoose-dompurify
```

## Usage

```javascript
const sanitizerPlugin = require('mongoose-dompurify');

MyMongooseSchema.plugin(sanitizerPlugin, {
  // Do not sanitize these fields (default: [])
  skip: [],

  // Encode HTML entities? (default: false)
  encodeHtmlEntities: false,

  // Configure DOMPurify, see https://github.com/cure53/DOMPurify for a list of options (default: undefined)
  sanitizer: {
    SAFE_FOR_JQUERY: true,
    SAFE_FOR_TEMPLATES: true,
    ALLOWED_TAGS: []
  }
});
```

When saving a document generated with `MyMongooseSchema`, mongoose-dompurify will automatically perform sanitization before saving to the database.

## License

(The MIT License)

Copyright (c) 2017 Jonathon Hill <jhill9693@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
