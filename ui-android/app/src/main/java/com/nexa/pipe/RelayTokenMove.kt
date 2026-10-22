package com.nexa.pipe

/**
 * What to do with a relay token an older version left in the backed-up
 * preferences.
 *
 * Split out of the migration so the decision can be tested without a device:
 * what happens to a credential is worth more than a line of bookkeeping.
 */
sealed interface RelayTokenMove {
    /**
     * There is no token — the value saved whenever a relay needs none.
     *
     * Not a credential, so nothing is written anywhere; the key is only
     * removed, so the file does not carry one that looks like a credential.
     */
    data object None : RelayTokenMove

    /** The token moves into the secrets file, sealed. */
    data class Move(val sealed: String) : RelayTokenMove

    /**
     * The token cannot be sealed on this device, so it stays where it is.
     *
     * The alternative is writing it in the clear into the file whose whole
     * point is that it holds ciphertext — and it is removed from the file it
     * came out of only once the sealed copy is written, so the value is never
     * lost.
     *
     * "Where it is" is the **backed-up** preferences: the ordinary
     * preferences file is part of the device's backup, of device-to-device
     * transfer and of cloud backup, and only the secrets file is excluded
     * from it (see `res/xml/backup_rules.xml`). So a token this device cannot
     * seal rides the backup for as long as the keystore stays unavailable —
     * the window runs from the first start without a keystore to the first
     * start with one, and the migration moves the token on that first start.
     *
     * Writing it in the clear into the secrets file would be a different
     * trade rather than a better one: that file is excluded from the backup,
     * so the token would stop riding it — but it would sit among values that
     * are all ciphertext, in a file every reader takes for a store of
     * protected credentials.
     *
     * Staying where it is also keeps it usable: the read path looks there
     * as well, so a token this device cannot seal is still the token the
     * tunnel authenticates with.
     */
    data object Keep : RelayTokenMove
}

/**
 * Decides what happens to a relay token on the way out of the backed-up
 * preferences.
 *
 * `seal` returns null when this device cannot seal the value, which is the
 * question the decision turns on: a token that cannot be sealed moves
 * nowhere.
 */
internal fun relayTokenMove(
    token: String,
    seal: (String) -> String?
): RelayTokenMove = when {
    token.isBlank() -> RelayTokenMove.None
    else -> seal(token)?.let { RelayTokenMove.Move(it) } ?: RelayTokenMove.Keep
}

/**
 * Reads the relay token out of the two places it can be.
 *
 * The secrets file is where the token lives once it has been sealed. The
 * backed-up preferences are where it lives when this device cannot seal it —
 * the rule [relayTokenMove] follows — so they are read as well: a token that
 * stayed there is still the user's token, and the relay is handed it
 * verbatim.
 *
 * The secrets file wins when it holds one: it is written whenever the token
 * is saved, so it holds the newer of the two, and what is left in the
 * backed-up file is the copy from before the token moved.
 *
 * The legacy value is read as it stands. It was written in the clear, and
 * unsealing it could only lose a token that happens to look sealed.
 */
internal fun relayTokenRead(
    stored: String?,
    legacy: String?,
    unseal: (String?) -> String
): String {
    val fromSecrets = stored?.let { unseal(it) }.orEmpty()
    if (fromSecrets.isNotBlank()) return fromSecrets
    return legacy?.takeIf { it.isNotBlank() } ?: ""
}
