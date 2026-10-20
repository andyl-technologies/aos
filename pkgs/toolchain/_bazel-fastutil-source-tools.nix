##! Source-built ProGuard inputs for Bazel's Java 8 fastutil trimming action.
{
  proguard,
  jdk8,
  platformClasspath ? "platformclasspath",
}: ''
  cp ${proguard}/share/java/proguard-base-${proguard.version}.jar \
    third_party/aos-proguard.jar
  mkdir -p third_party/java/proguard/proguard6.2.2/lib
  cp ${proguard}/share/java/proguard-base-${proguard.version}.jar \
    third_party/java/proguard/proguard6.2.2/lib/proguard.jar

  # Bazel distributes ProGuard 6.2.2. Use that source-built CLI for the
  # Java 8 fastutil input, with its matching source-built library classpath.
  test "$(grep -Fc 'runtime_deps = ["@maven//:com_guardsquare_proguard_base"],' third_party/BUILD)" = 1
  test "$(grep -Fc '"@rules_java//toolchains:${platformClasspath}",' third_party/BUILD)" = 1
  test "$(grep -Fc '$(execpath @rules_java//toolchains:${platformClasspath})' third_party/BUILD)" = 1
  sed -i \
    -e 's|runtime_deps = \["@maven//:com_guardsquare_proguard_base"\],|runtime_deps = [":source_proguard", "@maven//:com_google_code_gson_gson"],|' \
    -e '/"@rules_java\/\/toolchains:${platformClasspath}",/d' \
    -e 's|$(execpath @rules_java//toolchains:${platformClasspath})|${jdk8}/jre/lib/rt.jar|' \
    third_party/BUILD

  cat >> third_party/BUILD <<'BUILD'

  java_import(
      name = "source_proguard",
      jars = [":aos-proguard.jar"],
  )
  BUILD
''
