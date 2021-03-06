OAuth plugin for Burp Suite
===========================

[![Build Status](https://travis-ci.org/dnet/burp-oauth.svg?branch=master)](https://travis-ci.org/dnet/burp-oauth)

Building
--------

 - Install the dependencies, in case of libraries, put the JARs into `lib`
 - Copy `OAuthConfig.sample.java` to `src/burp/OAuthConfig.java` and modify it to your needs
 - Execute `ant`, and you'll have the plugin ready in `burp-oauth.jar`

Dependencies
------------

 - JDK 1.6+ (tested on OpenJDK 6 and Oracle JDK 7 + 8, recommended Debian/Ubuntu package: `openjdk-8-jdk`)
 - Apache ANT (Debian/Ubuntu package: `ant`)
 - `oauth-signpost` https://github.com/mttkay/signpost
 - Apache Commons Codecs: http://commons.apache.org/codec/
 - JUnit 4+ (only required for testing)

License
-------

The whole project is available under MIT license, see `LICENSE.txt`.

Known limitations
-----------------

 - Configuration has to be done at compile time using `OAuthConfig.java`
