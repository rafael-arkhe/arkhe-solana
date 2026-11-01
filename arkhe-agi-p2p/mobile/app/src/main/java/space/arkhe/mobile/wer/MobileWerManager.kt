package space.arkhe.mobile.wer

data class MobileWerRecord(
    val version: Int,
    val deviceAttestationHash: String,
    val appId: String,
    val actionName: String,
    val inputDigest: String,
    val outputDigest: String,
    val policyDigest: String,
    val performedAt: Long,
    val evidenceRefs: List<String>
)

class MobileWerManager {
    fun createRecord(
        deviceAttestationHash: String,
        appId: String,
        actionName: String,
        inputDigest: String,
        outputDigest: String,
        policyDigest: String,
        evidenceRefs: List<String>
    ): MobileWerRecord {
        return MobileWerRecord(
            version = 1,
            deviceAttestationHash = deviceAttestationHash,
            appId = appId,
            actionName = actionName,
            inputDigest = inputDigest,
            outputDigest = outputDigest,
            policyDigest = policyDigest,
            performedAt = System.currentTimeMillis() / 1000,
            evidenceRefs = evidenceRefs
        )
    }
}
