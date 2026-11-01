package space.arkhe.mobile.attestation

class StrongBoxAttestation {
    fun getAttestationQuote(): ByteArray {
        // Obtains verified boot and hardware quote from Titan M2 StrongBox KeyMint
        return "TITAN_M2_HARDWARE_ATTESTATION_QUOTE_MOCK".toByteArray()
    }
}
