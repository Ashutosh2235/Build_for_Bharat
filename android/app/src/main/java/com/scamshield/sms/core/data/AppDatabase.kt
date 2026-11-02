package com.scamshield.sms.core.data

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Upsert
import com.scamshield.sms.core.security.BlocklistLookup
import kotlinx.coroutines.flow.Flow
import java.util.concurrent.ConcurrentHashMap

/**
 * Server decision per SMS. `messageId` is the Telephony provider _id of the message.
 * verdict: PENDING | FRAUD | SPAM | NONE — the UI shows something ONLY for FRAUD and SPAM.
 * Message text itself is NOT stored here — it stays in the system SMS provider.
 */
@Entity(tableName = "scan_results")
data class ScanResultEntity(
    @PrimaryKey val messageId: Long,
    val threadId: Long,
    val sender: String,
    val status: String,               // PENDING | PARTIAL | COMPLETE (server)
    val verdict: String,              // PENDING | FRAUD | SPAM | NONE
    val score: Int,
    val reasonsJson: String,          // [{code,text,points,detail}]
    val urlsJson: String = "[]",      // server UrlOut list
    val serverScanId: String? = null,
    val impersonatedBrand: String? = null,
    val reportId: String? = null,
    val reportStatus: String? = null,
    val reportMode: String? = null,
    val reportIntendedJson: String? = null,
    val portalsJson: String? = null,
    val feedback: String? = null,     // scam | not_scam
    val canReport: Boolean = false,           // FRAUD, manual mode, not reported yet
    val reportPreviewJson: String? = null,    // ["Punjab State Cyber Crime Cell", …]
    val checksJson: String = "[]",            // message-level checks (sender database)
    val evidenceJson: String = "[]",          // codes that confirmed FRAUD
    val updatedAt: Long = System.currentTimeMillis(),
)

@Dao
interface ScanDao {
    @Upsert
    suspend fun upsert(e: ScanResultEntity)

    @Query("SELECT * FROM scan_results WHERE messageId = :id")
    suspend fun get(id: Long): ScanResultEntity?

    @Query("SELECT * FROM scan_results WHERE messageId = :id")
    fun observe(id: Long): Flow<ScanResultEntity?>

    @Query("SELECT * FROM scan_results WHERE threadId = :threadId")
    fun observeThread(threadId: Long): Flow<List<ScanResultEntity>>

    /** Worst verdict per thread for the conversation list chips. */
    @Query(
        "SELECT threadId, MAX(CASE verdict WHEN 'FRAUD' THEN 2 WHEN 'SPAM' THEN 1 ELSE 0 END) AS level " +
            "FROM scan_results GROUP BY threadId",
    )
    fun observeThreadLevels(): Flow<List<ThreadLevel>>

    @Query("SELECT * FROM scan_results WHERE reportId IS NOT NULL ORDER BY updatedAt DESC")
    fun observeReports(): Flow<List<ScanResultEntity>>

    @Query("SELECT * FROM scan_results WHERE status IN ('PENDING','PARTIAL')")
    suspend fun unfinished(): List<ScanResultEntity>
}

data class ThreadLevel(val threadId: Long, val level: Int)

@Entity(tableName = "blocked_senders")
data class BlockedSender(@PrimaryKey val norm: String)

@Entity(tableName = "blocked_domains")
data class BlockedDomain(@PrimaryKey val hash: String)

@Dao
interface BlocklistDao {
    @Query("SELECT norm FROM blocked_senders")
    suspend fun senders(): List<String>

    @Query("SELECT hash FROM blocked_domains")
    suspend fun domains(): List<String>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun addSenders(items: List<BlockedSender>)

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun addDomains(items: List<BlockedDomain>)

    @Query("DELETE FROM blocked_senders")
    suspend fun clearSenders()

    @Query("DELETE FROM blocked_domains")
    suspend fun clearDomains()
}

@Database(
    entities = [ScanResultEntity::class, BlockedSender::class, BlockedDomain::class],
    version = 2,   // 2: server-only decisions (FRAUD/SPAM), report mode — cache is rebuilt on upgrade
    exportSchema = true,
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun scanDao(): ScanDao
    abstract fun blocklistDao(): BlocklistDao

    companion object {
        fun build(context: Context): AppDatabase =
            Room.databaseBuilder(context, AppDatabase::class.java, "scamshield.db")
                .fallbackToDestructiveMigration()
                .build()
    }
}

/** In-memory view of the synced blocklist for the (synchronous) on-device scanner. */
class RoomBlocklist(private val dao: BlocklistDao) : BlocklistLookup {
    private val senders = ConcurrentHashMap.newKeySet<String>()
    private val domains = ConcurrentHashMap.newKeySet<String>()

    suspend fun load() {
        senders.clear(); senders.addAll(dao.senders())
        domains.clear(); domains.addAll(dao.domains())
    }

    suspend fun replace(full: Boolean, newSenders: List<String>, newDomainHashes: List<String>) {
        if (full) {
            dao.clearSenders(); dao.clearDomains()
        }
        dao.addSenders(newSenders.map(::BlockedSender))
        dao.addDomains(newDomainHashes.map(::BlockedDomain))
        load()
    }

    override fun isSenderBlocked(senderNorm: String) = senderNorm in senders
    override fun isDomainBlocked(domainHash: String) = domainHash in domains
}
