
name := "javallier"

organization := "com.n1analytics"

version := "0.3.4"

libraryDependencies ++= Seq(
  "ch.qos.logback" % "logback-classic" % "1.0.13",
  "com.novocode" % "junit-interface" % "0.11" % Test
)

javacOptions ++= Seq("-source", "1.8", "-target", "1.8")

// Solve issue where some loggers are initialised during configuration phase
testOptions in Test += Tests.Setup(classLoader =>
  classLoader
    .loadClass("org.slf4j.LoggerFactory")
    .getMethod("getLogger", classLoader.loadClass("java.lang.String"))
    .invoke(null, "ROOT"))

jacoco.settings
