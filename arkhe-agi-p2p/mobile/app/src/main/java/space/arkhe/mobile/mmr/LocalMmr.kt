package space.arkhe.mobile.mmr

class LocalMmr {
    private val leaves = mutableListOf<String>()

    fun append(leafDigestHex: String): Int {
        leaves.add(leafDigestHex)
        return leaves.size - 1
    }

    fun size(): Long {
        return leaves.size.toLong()
    }
}
