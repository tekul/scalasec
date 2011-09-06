resolvers ++= Seq(
    "Web plugin repo" at "http://siasia.github.com/maven2",
    "sbt-idea-repo" at "http://mpeltonen.github.com/maven/",
    "scct-repo" at "http://mtkopone.github.com/scct/maven-repo/"
    )

libraryDependencies += "com.github.mpeltonen" %% "sbt-idea" % "0.10.0"

libraryDependencies += "reaktor" % "scct-sbt-for-2.9" % "0.1-SNAPSHOT"

libraryDependencies <+= sbtVersion {v => "com.github.siasia" %% "xsbt-web-plugin" % ("0.1.1-"+v)}
