plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "de.androidcrypto.android_hce_emulate_a_creditcard"
    compileSdk = 34

    defaultConfig {
        applicationId = "de.androidcrypto.android_hce_emulate_a_creditcard"
        minSdk = 21
        targetSdk = 34
        versionCode = 5
        versionName = "1.4"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}

dependencies {
    implementation(libs.appcompat)
    implementation(libs.material)
    implementation(libs.activity)
    implementation(libs.constraintlayout)

    // Declared explicitly, not left to chance. recyclerview arrives today only
    // because material pulls it in, and localbroadcastmanager only because
    // fragment does. A bump to either parent drops them and you get a
    // "cannot find symbol" on a file you never touched.
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("androidx.localbroadcastmanager:localbroadcastmanager:1.1.0")

    // The card store holds PANs, track 2 data, the issuer key and the DD. It is
    // plaintext today, which means it is readable off a rooted device or an
    // adb backup. EncryptedSharedPreferences moves it behind a Keystore-held
    // AES key.
    //
    // 1.1.0-alpha06 rather than 1.0.0: alpha01 is the first release that runs
    // on API 21 and 22, and this app is minSdk 21. 1.0.0 would force a minSdk
    // bump. It is an alpha, so the API can still move - the whole point of
    // Prefs.java is that only one file has to change if it does.
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    testImplementation(libs.junit)
    androidTestImplementation(libs.ext.junit)
    androidTestImplementation(libs.espresso.core)

    // import und export complete credit card as GSON
    implementation("com.google.code.gson:gson:2.10.1")
}
