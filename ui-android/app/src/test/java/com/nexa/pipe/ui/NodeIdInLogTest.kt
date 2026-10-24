package com.nexa.pipe.ui

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The node id is the reachability credential.
 *
 * On a server started with `[auth] enabled = false` — the default, and what
 * the shipped example config uses — anybody who learns the node id completes
 * the handshake and reaches every route. 2FA closes that, but it is a second
 * factor the operator has to turn on, so the node id is the credential until
 * they do.
 *
 * The log panel keeps the last hundred lines, and a screenshot of it is a
 * screenshot of the machine's inventory. Nine call sites already truncate the
 * id to its first eight characters; six did not, and one of those was the
 * invite importer, which truncated the very same value for its toast four
 * lines after writing it in full.
 *
 * This checks the rule over the whole app rather than over the call sites
 * this branch touched, because the rule is what matters: a node id in the
 * log is a credential in the log, and the next call site that forgets is not
 * going to be caught by anything else.
 */
class NodeIdInLogTest {

    /**
     * The names that hold a node id in this app.
     *
     * `node.nodeId` is covered by the same rule as `nodeId`: the last
     * segment is what names the value.
     */
    private val nodeIdNames = setOf("nodeId", "oldNodeId", "newNodeId", "newId", "id")

    @Test
    fun no_log_line_prints_a_node_id_in_full() {
        val offenders = mutableListOf<String>()
        for (file in kotlinSources()) {
            val text = file.readText()
            for ((offset, arguments) in logCalls(text)) {
                val line = text.take(offset).count { it == '\n' } + 1
                for (expression in templates(arguments)) {
                    if (!isNodeId(expression)) continue
                    offenders += "${file.name}:$line  $expression"
                }
            }
        }
        assertTrue(
            "a node id in the log is the reachability credential in the log; " +
                "truncate it to its first eight characters:\n" +
                offenders.joinToString("\n"),
            offenders.isEmpty()
        )
    }

    /**
     * Whether a template expression prints a node id.
     *
     * The truncated form is not a leak: `take(8)` is what the other call
     * sites do, and it is the whole of the answer.
     */
    private fun isNodeId(expression: String): Boolean {
        val trimmed = expression.trim()
        if (trimmed.contains("take(")) return false
        return trimmed.substringAfterLast('.') in nodeIdNames
    }

    /**
     * The expressions a string template interpolates.
     *
     * Both forms count: `${name}` and the short `$name`, which ends at the
     * first character that is not part of the name — so `$name.take(8)` is
     * the *name* followed by the literal text ".take(8)", which is why every
     * call site writes the braces.
     */
    private fun templates(text: String): List<String> {
        val out = mutableListOf<String>()
        for (match in Regex("\\$\\{([^}]*)}").findAll(text)) out += match.groupValues[1]
        for (match in Regex("\\$([A-Za-z_][A-Za-z0-9_]*)").findAll(text)) out += match.groupValues[1]
        return out
    }

    /**
     * The arguments of every call that writes to the log panel, with the
     * offset the call starts at.
     *
     * The panel is written through `addLog` in the view model and through
     * `log.log` in the connector; both end up in the same hundred lines.
     */
    private fun logCalls(text: String): List<Pair<Int, String>> {
        val out = mutableListOf<Pair<Int, String>>()
        for (match in Regex("\\b(?:addLog|log\\.log)\\s*\\(").findAll(text)) {
            var depth = 0
            var index = match.range.last + 1
            val start = index
            while (index < text.length) {
                when (text[index]) {
                    '(' -> depth++
                    ')' -> {
                        depth--
                        if (depth == 0) break
                    }
                }
                index++
            }
            out += match.range.first to text.substring(start, minOf(index, text.length))
        }
        return out
    }

    /**
     * Every Kotlin source file of the app.
     */
    private fun kotlinSources(): List<File> {
        val root = sourceRoot()
        return root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .toList()
    }

    /**
     * The `src/main/java` directory of the app module.
     *
     * Walked up from the working directory, because the directory a unit test
     * runs in is the module's, and where that is depends on the build.
     */
    private fun sourceRoot(): File {
        var directory: File? = File("").absoluteFile
        while (directory != null) {
            val candidate = File(directory, "src/main/java")
            if (candidate.isDirectory) return candidate
            directory = directory.parentFile
        }
        throw AssertionError(
            "could not find src/main/java above ${File("").absolutePath}"
        )
    }
}
