#!/usr/bin/env bash
# Compile the pure-Kotlin security core on the JVM and check it produces exactly the same
# scores/verdicts/reasons as the Python backend. Needs: JDK 17+, a Kotlin compiler jar set
# (KOTLIN_LIB=dir with kotlin-compiler-embeddable, kotlin-stdlib, kotlinx-serialization-*-jvm …).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB="${KOTLIN_LIB:-/opt/gradle/lib}"
OUT="${TMPDIR:-/tmp}/scamshield-parity"
CORPUS="${1:-$ROOT/backend/tests/corpus/sms_corpus.jsonl}"
mkdir -p "$OUT"
CP="$(ls "$LIB"/*.jar | tr '\n' ':')"
SRC="$ROOT/android/app/src/main/java/com/scamshield/sms/core/security"

java -cp "$CP" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler -no-stdlib -no-reflect \
  -classpath "$LIB/kotlin-stdlib-2.0.21.jar:$(ls "$LIB"/kotlinx-serialization-*.jar | tr '\n' ':')" \
  -d "$OUT/classes" "$SRC"/*.kt "$ROOT/tools/parity/Parity.kt" 2>&1 | grep -v "^warning" || true

java -Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8 -cp "$OUT/classes:$LIB/kotlin-stdlib-2.0.21.jar:$(ls "$LIB"/kotlinx-serialization-*.jar | tr '\n' ':')" \
  ParityKt "$ROOT/android/app/src/main/assets" "$CORPUS" > "$OUT/kotlin.jsonl"

python3 "$ROOT/tools/parity/check_parity.py" "$OUT/kotlin.jsonl" "$CORPUS"
