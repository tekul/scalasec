import sbt._
import Keys._

import com.github.siasia.WebPlugin._

object BuildSettings {
  val buildOrganization = "scalasec"
  val buildVersion      = "0.1-SNAPSHOT"
  val buildScalaVersion = "2.9.1"

  import Resolvers._

  val buildSettings = Defaults.defaultSettings ++ Seq (
    resolvers ++= Seq(mavenLocalRepo, springSnapshotRepo),
    organization := buildOrganization,
    version      := buildVersion,
    scalaVersion := buildScalaVersion
  )
}

object Resolvers {
  val mavenLocalRepo = "Local Maven Repository" at "file://"+Path.userHome+"/.m2/repository"
  val springSnapshotRepo = "Spring Snapshot Repo" at "http://maven.springframework.org/snapshot"
}

object Dependencies {
  val springSecurityVersion = "3.1.0.CI-SNAPSHOT"
  val logbackVersion = "0.9.28"
  val slf4jVersion   = "1.6.1"

  def springSecurity(name: String) = "org.springframework.security" % "spring-security-%s".format(name) % springSecurityVersion

  val springSecurityCore = springSecurity("core")
  val springSecurityWeb = springSecurity("web")
  val springSecurityConfig = springSecurity("config")
  val springSecurityOpenid = springSecurity("openid")

  val servletapi = "javax.servlet" % "servlet-api" % "2.5"

  val scalaTest  = "org.scalatest" %% "scalatest" % "1.6.1" % "test->default"
  val specs2     = "org.specs2" %% "specs2" % "1.6.1" % "test"
  val specs2scalaz  = "org.specs2" %% "specs2-scalaz-core" % "6.0.1" % "test"
  val mockito    = "org.mockito" % "mockito-all" % "1.8.5" % "test->default"

  val jetty6     = "org.mortbay.jetty" % "jetty" % "6.1.26" % "jetty"
  val jetty7     = "org.eclipse.jetty" % "jetty-webapp" % "7.5.0.v20110901" % "jetty"

  val slf4j      = "org.slf4j" % "slf4j-api" % slf4jVersion
  val logback    = "ch.qos.logback" % "logback-classic" % logbackVersion % "runtime->default"
  val jcl        = "org.slf4j" %  "jcl-over-slf4j" % slf4jVersion % "runtime->default"

  val cglib      = "cglib" % "cglib-nodep" % "2.2.2" % "runtime->default"
}

object ScalaSecBuild extends Build {
  import Dependencies._
  import BuildSettings._

  val springSecDeps = Seq(springSecurityCore, springSecurityWeb, springSecurityConfig, springSecurityOpenid)
  val testDeps = Seq(scalaTest, specs2, specs2scalaz, mockito)
  val loggingDeps = Seq(slf4j, jcl, logback)

  lazy val scalasec = Project("scalasec",
    file("."),
    settings = buildSettings
  ) aggregate (core, testapp)

  lazy val core = Project("core",
    file("core"),
    settings = buildSettings ++ Seq (
      libraryDependencies ++= testDeps ++ loggingDeps ++ springSecDeps ++ Seq(servletapi, cglib)
    )
  )

  lazy val testapp = Project("testapp",
    file("testapp"),
    settings = buildSettings ++ webSettings ++ Seq(
      libraryDependencies ++= testDeps ++ loggingDeps :+ jetty7
    )
  ) dependsOn (core)
}
