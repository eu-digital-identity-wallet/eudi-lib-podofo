
object Meta {
    const val BASE_URL = "https://github.com/eu-digital-identity-wallet/eudi-lig-podofo"
}

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.maven.publish)
}

android {
    namespace = "com.podofo.android"
    compileSdk = 34

    defaultConfig {
        minSdk = 26
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.toVersion(libs.versions.java.get())
        targetCompatibility = JavaVersion.toVersion(libs.versions.java.get())
    }
}

dependencies {
    implementation(libs.appcompat)
}

mavenPublishing {
    pom {
        name.set(project.name)
        description.set("EUDI PoDoFo library for Android")
        url.set(Meta.BASE_URL)

        ciManagement {
            system = "github"
            url = Meta.BASE_URL + "/actions"
        }
        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            developer {
            }
        }
        scm {
            connection.set("scm:git:" + Meta.BASE_URL + ".git")
            developerConnection.set("scm:git:ssh://git@github.com" + Meta.BASE_URL.substringAfter("https://github.com") + ".git")
            url.set(Meta.BASE_URL)
        }
    }
}