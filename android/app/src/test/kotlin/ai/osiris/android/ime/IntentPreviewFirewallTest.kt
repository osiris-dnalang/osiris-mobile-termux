package ai.osiris.android.ime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class IntentPreviewFirewallTest {

    private lateinit var firewall: IntentPreviewFirewall

    @Before
    fun setUp() {
        firewall = DefaultIntentPreviewFirewall()
    }

    @Test
    fun testValidIgniteCommand() {
        val provenance = firewall.analyzeCommand("/ignite")
        assertTrue(provenance is AstProvenance.VerifiedKernelAst)
        val verified = provenance as AstProvenance.VerifiedKernelAst
        assertEquals("ignite", verified.toolName)
        assertEquals(RiskLevel.LOW, verified.riskLevel)
        assertEquals(false, verified.modifiesState)
    }

    @Test
    fun testValidLearnCommand() {
        val provenance = firewall.analyzeCommand("/learn 25")
        assertTrue(provenance is AstProvenance.VerifiedKernelAst)
        val verified = provenance as AstProvenance.VerifiedKernelAst
        assertEquals("learn", verified.toolName)
        assertEquals("25", verified.parameters["generations"])
        assertEquals(RiskLevel.LOW, verified.riskLevel)
        assertEquals(true, verified.modifiesState)
    }

    @Test
    fun testValidDnaIntentCommand() {
        val provenance = firewall.analyzeCommand("/dna \"compile XY4 dynamical decoupling sequence\"")
        assertTrue(provenance is AstProvenance.VerifiedKernelAst)
        val verified = provenance as AstProvenance.VerifiedKernelAst
        assertEquals("dna", verified.toolName)
        assertEquals("compile XY4 dynamical decoupling sequence", verified.parameters["intent"])
        assertEquals(RiskLevel.MODERATE, verified.riskLevel)
        assertEquals(true, verified.modifiesState)
    }

    @Test
    fun testAdversarialExecInjectionRejected() {
        // AT-SEC-11: Attempted dynamic evaluation injection
        val provenance = firewall.analyzeCommand("exec('import os; os.system(\"cat /etc/passwd\")')")
        assertTrue(provenance is AstProvenance.UnverifiedOrUntrusted)
        val unverified = provenance as AstProvenance.UnverifiedOrUntrusted
        assertTrue(unverified.firewallRejectionReason.contains("Prohibited execution token"))
    }

    @Test
    fun testDestructiveRmRfRejected() {
        val provenance = firewall.analyzeCommand("rm -rf /")
        assertTrue(provenance is AstProvenance.UnverifiedOrUntrusted)
        val unverified = provenance as AstProvenance.UnverifiedOrUntrusted
        assertTrue(unverified.detectedDangerousTokens.contains("rm -rf"))
    }

    @Test
    fun testChainedCommandRejected() {
        // No denylisted token here, so the chaining check (not the denylist) must catch it.
        val provenance = firewall.analyzeCommand("/ignite && /status")
        assertTrue(provenance is AstProvenance.UnverifiedOrUntrusted)
        val unverified = provenance as AstProvenance.UnverifiedOrUntrusted
        assertTrue(unverified.firewallRejectionReason.contains("multi-statement"))
    }

    @Test
    fun testTrailingOperatorRejected() {
        for (cmd in listOf("/status;", "/ledger |", "/status `")) {
            val provenance = firewall.analyzeCommand(cmd)
            assertTrue(cmd, provenance is AstProvenance.UnverifiedOrUntrusted)
        }
    }

    @Test
    fun testQuotedOperatorStillAllowed() {
        val provenance = firewall.analyzeCommand("/dna \"a; b | c\"")
        assertTrue(provenance is AstProvenance.VerifiedKernelAst)
    }

    @Test
    fun testProtectedTargetMutationRejected() {
        val provenance = firewall.analyzeCommand("write policy.json")
        assertTrue(provenance is AstProvenance.UnverifiedOrUntrusted)
        val unverified = provenance as AstProvenance.UnverifiedOrUntrusted
        assertTrue(unverified.firewallRejectionReason.contains("immutable governance artifact"))
    }
}
