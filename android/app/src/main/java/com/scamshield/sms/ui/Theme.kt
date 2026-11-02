package com.scamshield.sms.ui

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val Brand = Color(0xFF0B5D4B)
val ScamRed = Color(0xFFB3261E)
val WarnAmber = Color(0xFFB26A00)
val SafeGreen = Color(0xFF1E7B4F)

@Composable
fun ScamShieldTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val ctx = LocalContext.current
    val scheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> darkColorScheme(primary = Color(0xFF7FD6BC))
        else -> lightColorScheme(primary = Brand)
    }
    MaterialTheme(colorScheme = scheme, content = content)
}

/** Only the server's final decisions are ever shown. PENDING / NONE / anything else → nothing. */
fun isShown(verdict: String?): Boolean = verdict == "FRAUD" || verdict == "SPAM"

fun verdictColor(verdict: String?): Color = when (verdict) {
    "FRAUD" -> ScamRed
    "SPAM" -> WarnAmber
    else -> Color.Gray
}

fun verdictLabel(verdict: String?): String = when (verdict) {
    "FRAUD" -> "Surely fraud"
    "SPAM" -> "Surely spam"
    else -> ""
}

/** Draws nothing unless the verdict is FRAUD or SPAM. */
@Composable
fun VerdictChip(verdict: String?, modifier: Modifier = Modifier) {
    if (!isShown(verdict)) return
    Surface(color = verdictColor(verdict).copy(alpha = 0.14f), shape = RoundedCornerShape(50), modifier = modifier) {
        Text(
            verdictLabel(verdict),
            color = verdictColor(verdict),
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
        )
    }
}
