import sbt._
import Keys._

import com.github.siasia.WebPlugin._

object BuildSettings {
  val buildVersion      = "0.1-SNAPSHOT"
  val buildScalaVersion = "2.9.3"

  val buildSettings = Defaults.defaultSettings ++ Seq (
    organization := "eu.tekul",
    version      := buildVersion,
    scalaVersion := buildScalaVersion
  )
}

object Dependencies {
  val springSecurityVersion = "3.1.3.RELEASE"
  val springVersion  = "3.2.2.RELEASE"
  val logbackVersion = "1.0.11"
  val slf4jVersion   = "1.7.5"

  def springSecurity(name: String) = "org.springframework.security" % "spring-security-%s".format(name) % springSecurityVersion
  def spring(name: String)         = "org.springframework" % "spring-%s".format(name) % springVersion

  val springSecurityCore = springSecurity("core")
  val springSecurityWeb = springSecurity("web")
  val springSecurityConfig = springSecurity("config")
  val springSecurityOpenid = springSecurity("openid")

  val springDeps = Seq(spring("core"), spring("context"), spring("beans"), spring("aop"), spring("web"), spring("jdbc"), spring("tx"))

  val servletapi = "javax.servlet" % "servlet-api" % "2.5"

  val scalaTest = Seq(
    "org.scalatest" %% "scalatest" % "1.9.1" % "test"
//  , "org.scalacheck" %% "scalacheck" % "1.10.1" % "test"
  )

  val mockito    = "org.mockito" % "mockito-all" % "1.9.5" % "test"

  val jetty6     = "org.mortbay.jetty" % "jetty" % "6.1.26" % "container"
  val jetty7     = "org.eclipse.jetty" % "jetty-webapp" % "7.6.9.v20130131" % "container"

  val slf4j      = "org.slf4j" % "slf4j-api" % slf4jVersion
  val logback    = "ch.qos.logback" % "logback-classic" % logbackVersion % "runtime"
  val jcl        = "org.slf4j" %  "jcl-over-slf4j" % slf4jVersion % "runtime"

  val cglib      = "cglib" % "cglib-nodep" % "2.2.2" % "runtime"
}

object Build extends Build {
  import Dependencies._
  import BuildSettings._

  val springSecDeps = Seq(springSecurityCore, springSecurityWeb, springSecurityConfig, springSecurityOpenid)
  val testDeps = scalaTest ++ Seq(mockito)
  val loggingDeps = Seq(slf4j, jcl, logback)

  lazy val scalasec = Project("scalasec",
    file("."),
    settings = buildSettings
  ) aggregate (core, testapp)

  lazy val core = Project("spring-security-scala",
    file("core"),
    settings = buildSettings ++ Seq (
      libraryDependencies ++= testDeps ++ loggingDeps ++ springDeps ++ springSecDeps ++ Seq(servletapi, cglib)
    ) ++ Publish.settings
  )

  lazy val testapp = Project("testapp",
    file("testapp"),
    settings = buildSettings ++ webSettings ++ Seq(
      libraryDependencies ++= testDeps ++ loggingDeps ++ Seq(cglib) :+ jetty7
    )
  ) dependsOn (core)
}
