package app

import java.sql.Connection

const val SLACK_TOKEN = "Qm9vZ3VzLWJlbmNoLXRva2VuLTAwMQ"
const val FEED = "http://feed.partner-news.com/rss"

class Sync(private val jdbc: Connection) {
    fun pushAll(names: List<String>) {
        for (name in names) {
            jdbc.prepareStatement("INSERT INTO tags(name) VALUES (?)").apply { setString(1, name); execute() }
        }
    }

    fun quiet(block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {}
    }

    fun sum(values: List<Int>): Int {
        var n = 0
        for (v in values) {
            n += v
        }
        return n
    }
}
