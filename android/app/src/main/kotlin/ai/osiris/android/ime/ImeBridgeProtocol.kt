package ai.osiris.android.ime

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Wire contract between the OSIRIS keyboard and the Termux `osiris-ime-bridge` daemon
 * (`osiris_mobile/ime/server.py`).
 *
 * Pure JVM on purpose: no android.* imports, so it is unit-testable off-device. The HTTP
 * transport that calls it belongs in the InputMethodService.
 *
 * Signing mirrors the Python `sign_request` / `sign_reply` byte for byte. Both test
 * suites check the same golden vector, so a change on one side fails the other's tests.
 */
object ImeBridgeProtocol {
    const val PROTOCOL_VERSION = "1.0"
    const val DEFAULT_PORT = 8420
    const val HEADER_TIMESTAMP = "X-Osiris-Timestamp"
    const val HEADER_SIGNATURE = "X-Osiris-Signature"
    const val INTENT_DISPATCH_CARD = "tui.dispatch_card"

    /** Mirrors `control.Action.ALL`; a Python test reads this set from this file. */
    val ALLOWED_ACTIONS: Set<String> = setOf(
        "health.check", "ledger.verify", "nclm.status", "mentor.benchmark", "ledger.check_all"
    )

    /** Hosts where the keyboard opens the OSIRIS intent bar. Mirrors `clipboard.LLM_HOSTS`. */
    val LLM_HOSTS: Set<String> = setOf(
        "com.openai.chatgpt",
        "com.google.android.apps.bard",
        "com.anthropic.claude",
        "com.google.android.googlequicksearchbox"
    )

    // android.text.InputType values, inlined so this file stays JVM-testable.
    private const val TYPE_MASK_CLASS = 0x0000000f
    private const val TYPE_MASK_VARIATION = 0x00000ff0
    private const val TYPE_CLASS_TEXT = 0x00000001
    private const val TYPE_CLASS_NUMBER = 0x00000002
    private const val TYPE_TEXT_VARIATION_PASSWORD = 0x00000080
    private const val TYPE_TEXT_VARIATION_VISIBLE_PASSWORD = 0x00000090
    private const val TYPE_TEXT_VARIATION_WEB_PASSWORD = 0x000000e0
    private const val TYPE_NUMBER_VARIATION_PASSWORD = 0x00000010

    /**
     * Spec §6.3: on password fields the keyboard disables suggestions, voice, routing and
     * learning. Every request built for such a field must carry `sensitive_field: true`.
     */
    fun isSensitiveInputType(inputType: Int): Boolean {
        val variation = inputType and TYPE_MASK_VARIATION
        return when (inputType and TYPE_MASK_CLASS) {
            TYPE_CLASS_TEXT -> variation == TYPE_TEXT_VARIATION_PASSWORD ||
                variation == TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
                variation == TYPE_TEXT_VARIATION_WEB_PASSWORD
            TYPE_CLASS_NUMBER -> variation == TYPE_NUMBER_VARIATION_PASSWORD
            else -> false
        }
    }

    fun signRequest(key: ByteArray, method: String, path: String, timestampMs: Long, body: ByteArray): String {
        val message = "${method.uppercase()}\n$path\n$timestampMs\n${sha256Hex(body)}"
        return "v1=" + hmacHex(key, message.toByteArray(Charsets.UTF_8))
    }

    /** Constant-time check that a reply came from the paired daemon. */
    fun verifyReply(key: ByteArray, body: ByteArray, signature: String?): Boolean {
        if (signature == null) return false
        val expected = ("v1=" + hmacHex(key, body)).toByteArray(Charsets.UTF_8)
        return MessageDigest.isEqual(expected, signature.toByteArray(Charsets.UTF_8))
    }

    /**
     * RFC 9562 UUIDv7: 48-bit Unix-ms timestamp, version 7, 74 random bits. Time-ordered,
     * not deterministic: idempotency comes from reusing the same id on retry, which
     * [ControlRequest] does by holding it.
     */
    fun uuidV7(nowMs: Long = System.currentTimeMillis(), random: SecureRandom = SecureRandom()): UUID {
        val rand = ByteArray(10).also { random.nextBytes(it) }
        val msb = ((nowMs and 0xFFFFFFFFFFFFL) shl 16) or
            0x7000L or
            ((rand[0].toLong() and 0x0FL) shl 8) or
            (rand[1].toLong() and 0xFFL)
        var lsb = 0L
        for (i in 2 until 10) lsb = (lsb shl 8) or (rand[i].toLong() and 0xFFL)
        lsb = (lsb and 0x3FFFFFFFFFFFFFFFL) or Long.MIN_VALUE // variant 0b10
        return UUID(msb, lsb)
    }

    internal fun jsonString(value: String): String = buildString {
        append('"')
        for (ch in value) {
            when {
                ch == '"' -> append("\\\"")
                ch == '\\' -> append("\\\\")
                ch < ' ' -> append("\\u%04x".format(ch.code))
                else -> append(ch)
            }
        }
        append('"')
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).toHex()

    private fun hmacHex(key: ByteArray, message: ByteArray): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message).toHex()
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}

/**
 * One hinge-spine key press. Build it once and resend the same instance on retry: the
 * daemon answers a repeated task id with the cached result instead of running again.
 */
class ControlRequest(
    val actionName: String,
    val accelerator: String,
    val taskId: UUID = ImeBridgeProtocol.uuidV7(),
    val clientTimestampMs: Long = System.currentTimeMillis()
) {
    init {
        require(actionName in ImeBridgeProtocol.ALLOWED_ACTIONS) { "action '$actionName' is not allowlisted" }
        require(accelerator.length <= 4) { "accelerator must be at most 4 characters" }
    }

    fun toJson(): String {
        val q = ImeBridgeProtocol::jsonString
        return "{" +
            "\"protocol_version\":${q(ImeBridgeProtocol.PROTOCOL_VERSION)}," +
            "\"task_id\":${q(taskId.toString())}," +
            "\"origin\":${q("android.osiris.ime")}," +
            "\"intent\":${q(ImeBridgeProtocol.INTENT_DISPATCH_CARD)}," +
            "\"parameters\":{\"accelerator\":${q(accelerator)},\"action_name\":${q(actionName)}}," +
            "\"client_timestamp_ms\":$clientTimestampMs" +
            "}"
    }
}
