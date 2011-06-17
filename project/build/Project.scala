import sbt._

class MyProject(info: ProjectInfo) extends DefaultProject(info) {
    val secVersion = "3.1.0.CI-SNAPSHOT"

    val seccore    = "org.springframework.security" % "spring-security-core" % secVersion % "compile->default" withSources()
    val secweb     = "org.springframework.security" % "spring-security-web" % secVersion % "compile->default" withSources()
    val seccfg     = "org.springframework.security" % "spring-security-config" % secVersion % "compile->default" withSources()
    val servletapi = "javax.servlet" % "servlet-api" % "2.5" % "compile->default" withSources()
    val scalatest = "org.scalatest" % "scalatest_2.9.0" % "1.6.1"
    //val specs      = "org.scala-tools.testing" %% "specs" % "1.6.6" % "test->default"

    val mavenLocal = "Local Maven Repository" at "file://"+Path.userHome+"/.m2/repository"
}
