// Resolves the coordinates -PprobeDeps lists, comma-separated, without their
// transitive dependencies, through the repositories settings.gradle.kts names,
// and prints each file it resolved. The settings and the wrapper beside it are
// mvdatacenter/paul-operations' own, unchanged.
val probe by configurations.creating { isTransitive = false }

dependencies {
    (findProperty("probeDeps") as String?)?.split(",")?.forEach { add("probe", it) }
}

tasks.register("probe") {
    val files = probe
    doLast {
        files.resolvedConfiguration.resolvedArtifacts.forEach {
            println("resolved ${it.moduleVersion.id} ${it.file.name}")
        }
    }
}
