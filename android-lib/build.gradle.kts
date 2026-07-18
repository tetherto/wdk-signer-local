plugins {

    id("com.android.library")
}
android {
    namespace = "com.tetherto.bare.signer"
    compileSdk = 36

    defaultConfig {
        minSdk = 29
        externalNativeBuild {
            cmake {
                arguments += listOf("-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON")
            }
        }

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
kotlin {
    jvmToolchain(17)
}


val npmAndroidDir = layout.projectDirectory.dir("../libs/android")

tasks.register<Copy>("copyAarToNpmAndroid") {
    dependsOn("assembleRelease")
    val aar = layout.buildDirectory.file("outputs/aar/${project.name}-release.aar")
    from(aar)
    into(npmAndroidDir)
    rename { "bare-signer-android.aar" }
}
dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.fragment:fragment-ktx:1.7.1")
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
}
