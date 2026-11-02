// JVM harness: runs the Android on-device scanner over a JSONL corpus and prints one JSON line
// per message, so tools/parity/check_parity.py can compare it with the Python backend.
import com.scamshield.sms.core.security.LocalScanner
import com.scamshield.sms.core.security.RuleSet
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File

fun main(args: Array<String>) {
    val assets = File(args[0])
    val rs = RuleSet.parse(File(assets, "rules.json").readText(), File(assets, "brands.json").readText())
    val scanner = LocalScanner(rs)
    File(args[1]).readLines().filter { it.isNotBlank() }.forEach { line ->
        val o = Json.parseToJsonElement(line).jsonObject
        val r = scanner.scan(o.getValue("sender").jsonPrimitive.content, o.getValue("text").jsonPrimitive.content)
        val codes = r.score.signals.map { it.code }.sorted().joinToString(",") { "\"$it\"" }
        val urls = r.urls.joinToString(",") { "\"" + it.replace("\\", "\\\\").replace("\"", "\\\"") + "\"" }
        println("{\"score\":${r.score.score},\"verdict\":\"${r.score.verdict}\",\"codes\":[$codes],\"urls\":[$urls]}")
    }
}
