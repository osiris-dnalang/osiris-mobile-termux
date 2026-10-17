package ai.osiris.android.ime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class ImeBridgeProtocolTest {

    private val key = ByteArray(32) { it.toByte() }
    private val body = "{\"a\":1}".toByteArray(Charsets.UTF_8)

    // Same vector as tests/test_ime_protocol_parity.py on the Python side.
    @Test
    fun requestSignatureMatchesPythonGoldenVector() {
        assertEquals(
            "v1=85e7d70df2d953abe96f49f4c06b547d6ee8cbe1dbeeee46df5d8d12ac2efa87",
            ImeBridgeProtocol.signRequest(key, "post", "/v1/control/dispatch", 1792103040000L, body)
        )
    }

    @Test
    fun replySignatureMatchesPythonGoldenVector() {
        val sig = "v1=b4cebde30982443ec36c18fa99ad10a70e705bba779f57c37e84decb64ae50fb"
        assertTrue(ImeBridgeProtocol.verifyReply(key, body, sig))
        assertFalse(ImeBridgeProtocol.verifyReply(key, "{\"a\":2}".toByteArray(), sig))
        assertFalse(ImeBridgeProtocol.verifyReply(key, body, null))
    }

    @Test
    fun uuidV7CarriesVersionVariantAndTimestamp() {
        val now = 1792103040000L
        val id = ImeBridgeProtocol.uuidV7(now, SecureRandom())
        assertEquals(7, id.version())
        assertEquals(2, id.variant())
        assertEquals(now, id.mostSignificantBits ushr 16)
    }

    @Test
    fun uuidV7IsTimeOrdered() {
        val a = ImeBridgeProtocol.uuidV7(1_000L)
        val b = ImeBridgeProtocol.uuidV7(2_000L)
        assertTrue(a.toString() < b.toString())
    }

    @Test
    fun controlRequestJsonIsStableForRetries() {
        val req = ControlRequest("health.check", "1")
        assertEquals(req.toJson(), req.toJson())
        assertTrue(req.toJson().contains("\"task_id\":\"${req.taskId}\""))
        assertTrue(req.toJson().contains("\"action_name\":\"health.check\""))
    }

    @Test(expected = IllegalArgumentException::class)
    fun controlRequestRejectsNonAllowlistedAction() {
        ControlRequest("shell.exec", "1")
    }

    @Test
    fun jsonStringEscapes() {
        assertEquals("\"a\\\"b\\\\c\\u000a\"", ImeBridgeProtocol.jsonString("a\"b\\c\n"))
    }

    @Test
    fun passwordFieldsAreSensitive() {
        val text = 0x1
        assertTrue(ImeBridgeProtocol.isSensitiveInputType(text or 0x80))  // TEXT_VARIATION_PASSWORD
        assertTrue(ImeBridgeProtocol.isSensitiveInputType(text or 0x90))  // VISIBLE_PASSWORD
        assertTrue(ImeBridgeProtocol.isSensitiveInputType(text or 0xe0))  // WEB_PASSWORD
        assertTrue(ImeBridgeProtocol.isSensitiveInputType(0x2 or 0x10))   // NUMBER_VARIATION_PASSWORD
        assertFalse(ImeBridgeProtocol.isSensitiveInputType(text))
        assertFalse(ImeBridgeProtocol.isSensitiveInputType(text or 0x20)) // EMAIL_ADDRESS
    }

    @Test
    fun firewallPreviewsCarryNoRefutedConstants() {
        val markers = Regex("(?i)(θ|theta)[ _]?lock|51\\.843|(Γ|gamma)[ _]?floor|0\\.0920|11\\s*-?\\s*D\\s*-?\\s*CRSM")
        val firewall = DefaultIntentPreviewFirewall()
        for (cmd in listOf("/ignite", "/learn 10", "/dna \"x\"", "/ledger", "/status", "/sim 5")) {
            val preview = firewall.analyzeCommand(cmd) as AstProvenance.VerifiedKernelAst
            assertFalse("$cmd preview: ${preview.description}", markers.containsMatchIn(preview.description))
        }
    }
}
