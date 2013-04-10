Spring Security Configuration with Scala
========================================

Code to accompany [this blog article](http://blog.springsource.org/2011/08/01/spring-security-configuration-with-scala/).

Provides a scala-based alternative to the usual Spring Security namespace with similar syntax, but which is compatible with Spring's `@Configuration` features. It is no more complicated than namespace syntax, but is more powerful and intuitive as it directly exposes the actual classes which are usually hidden. By using higher-order functions, it makes it easy to plug in new behaviour for features such as access-control (`interceptUrl`), which can e directly implemented as Scala functions.


Building
--------

The code is built and run using sbt

1. [Download and install](http://www.scala-sbt.org/release/docs/Getting-Started/Setup.html) version 0.12.3
2. `cd scalasec`
3. `sbt`


Running the Sample app
----------------------

Then from the sbt prompt, build and run using

1. `update`
2. `compile`
3. `container:start`

Browse to http://localhost:8080/anyurl/

Log in in with any username and password=username.

