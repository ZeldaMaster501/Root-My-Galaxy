package dev.busung.s25uroot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

class TargetProfileTest {
    private val profile = TargetProfile(
        profileId = "galaxy-s25-series-kernel-6.6.98",
        displayName = "Galaxy S25 series",
        models = setOf("SM-S931B", "SM-S938N"),
        kernelVersions = setOf("6.6.98"),
        exploit = RemoteArtifact("https://example.invalid/exploit", 1),
        kernelSu = RemoteArtifact("https://example.invalid/ksud", 1),
    )

    @Test
    fun matchesRegionalS25OnSameKernelVersion() {
        assertTrue(profile.matches(snapshot("SM-S931B", "6.6.98-android15-8-build-a")))
        assertTrue(profile.matches(snapshot("SM-S938N", "6.6.98-android15-8-build-b")))
    }

    @Test
    fun rejectsUnlistedModelOrKernelVersion() {
        assertFalse(profile.matches(snapshot("SM-S928B", "6.6.98-android15-8-build")))
        assertFalse(profile.matches(snapshot("SM-S938N", "6.6.102-android15-8-build")))
    }

    @Test
    fun rejectsDifferentFirmwareWhenProfileDeclaresExactBuild() {
        val exactProfile = profile.copy(
            models = setOf("SM-S928U"),
            kernelVersions = setOf("6.1.145"),
            kernelReleases = setOf("6.1.145-android14-11-33419968-abS928USQS6DZF2"),
            buildIds = setOf("BP4A.251205.006.S928USQS6DZF2"),
        )

        assertTrue(
            exactProfile.matches(
                snapshot(
                    "SM-S928U",
                    "6.1.145-android14-11-33419968-abS928USQS6DZF2",
                    "BP4A.251205.006.S928USQS6DZF2",
                ),
            ),
        )
        assertFalse(
            exactProfile.matches(
                snapshot(
                    "SM-S928U",
                    "6.1.145-android14-11-33419968-abS928USQS6DZG1",
                    "BP4A.251205.006.S928USQS6DZG1",
                ),
            ),
        )
    }

    @Test
    fun parsesExactBuildAndAttemptControls() {
        val manifest = SupportManifest.parse(
            """
            {
              "schemaVersion": 4,
              "payloads": [{
                "payloadId": "e3q-test",
                "displayName": "E3Q test",
                "models": ["SM-S928U"],
                "kernelVersions": ["6.1.145"],
                "kernelReleases": ["release-exact"],
                "buildIds": ["build-exact"],
                "exploitAttempts": 1,
                "requiresFreshP0Session": true,
                "exploit": {"url": "https://example.invalid/exploit", "size": 1},
                "kernelsu": {"url": "https://example.invalid/ksud", "size": 1}
              }]
            }
            """.trimIndent().toByteArray(),
        ).targets.single()

        assertEquals(setOf("release-exact"), manifest.kernelReleases)
        assertEquals(setOf("build-exact"), manifest.buildIds)
        assertEquals(1, manifest.exploitAttempts)
        assertTrue(manifest.requiresFreshP0Session)
    }

    @Test
    fun rejectsLegacyManifestWithoutExactBuildSemantics() {
        assertThrows(IllegalArgumentException::class.java) {
            SupportManifest.parse(
                """{"schemaVersion":3,"payloads":[]}""".toByteArray(),
            )
        }
    }

    private fun snapshot(
        model: String,
        kernelRelease: String,
        buildId: String = "BP4A.251205.006.S938BCZG1",
    ) = DeviceSnapshot(
        manufacturer = "samsung",
        model = model,
        device = "unused",
        kernelRelease = kernelRelease,
        kernelVersionInfo = "#1 SMP PREEMPT",
        machine = "aarch64",
        buildId = buildId,
        fingerprint = "samsung/example",
        androidRelease = "16",
        sdk = 36,
        abi = "arm64-v8a",
        pageSize = 4096,
    )
}
