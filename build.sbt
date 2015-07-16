name := "javallier"

version := "0.4.0"

description := "A Java library for Paillier partially homomorphic encryption."

organization := "com.n1analytics"

organizationName := "N1 Analytics"

organizationHomepage := Some(url("https://n1analytics.com"))

licenses += "Apache 2.0" -> url("https://www.apache.org/licenses/LICENSE-2.0")

exportJars := true

libraryDependencies ++= Seq(
  "ch.qos.logback" % "logback-classic" % "1.0.13",
  "com.novocode" % "junit-interface" % "0.11" % Test
)

// Solve issue where some loggers are initialised during configuration phase
testOptions in Test += Tests.Setup(classLoader =>
  classLoader
    .loadClass("org.slf4j.LoggerFactory")
    .getMethod("getLogger", classLoader.loadClass("java.lang.String"))
    .invoke(null, "ROOT"))

jacoco.settings
