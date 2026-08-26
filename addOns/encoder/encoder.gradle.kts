import org.zaproxy.gradle.addon.AddOnStatus

description =
    "Adds encode/decode/hash dialog, support for scripted processors, and in-place encode/decode/hash/convert operations"

zapAddOn {
    addOnName.set("Encoder")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/encode-decode-hash/")
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">=1.23.0")
                }
            }
        }
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}

dependencies {
    zapAddOn("commonlib")

    implementation("org.bouncycastle:bcprov-jdk18on:1.83")
    implementation("io.github.rctcwyvrn:blake3:1.3")

    testImplementation(project(":testutils"))
}
