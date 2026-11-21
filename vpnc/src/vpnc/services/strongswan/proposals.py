"""strongSwan's proposal keywords, and its checks of a proposal.

As strongSwan 6.0 has them (proposal_keywords_static.txt, proposal.c), so a
proposal is checked when it's staged, before charon gets it. Each keyword has
its transform type and algorithm, named as charon's get-algorithms names it.
"""

from __future__ import annotations

import difflib

ENCRYPTION = "ENCRYPTION"
INTEGRITY = "INTEGRITY"
PRF = "PRF"
KE = "KE"
ESN = "ESN"
# Transform types in the order they're written.
TYPES = (ENCRYPTION, INTEGRITY, PRF, KE, ESN)
# The groups of charon's get-algorithms per transform type.
GROUPS = {
    ENCRYPTION: ("encryption", "aead"),
    INTEGRITY: ("integrity",),
    PRF: ("prf",),
    # strongSwan 5 calls them dh.
    KE: ("ke", "dh"),
}

# Combined-mode encryption: no integrity algorithm with it.
AEAD = {
    "AES_CCM_8",
    "AES_CCM_12",
    "AES_CCM_16",
    "AES_GCM_8",
    "AES_GCM_12",
    "AES_GCM_16",
    "NULL_AES_GMAC",
    "CAMELLIA_CCM_8",
    "CAMELLIA_CCM_12",
    "CAMELLIA_CCM_16",
    "CHACHA20_POLY1305",
}
# Integrity algorithms an IKE proposal without a PRF takes its PRF from.
PRF_FROM_INTEGRITY = {
    "HMAC_SHA1_96",
    "HMAC_SHA1_160",
    "HMAC_SHA2_256_128",
    "HMAC_SHA2_384_192",
    "HMAC_SHA2_512_256",
    "HMAC_MD5_96",
    "HMAC_MD5_128",
    "AES_XCBC_96",
    "CAMELLIA_XCBC_96",
    "AES_CMAC_96",
}


def _keywords() -> dict[str, tuple[str, str | None]]:  # noqa: C901 (the table)
    """Return the keywords: their transform type and algorithm (None: none)."""
    found: dict[str, tuple[str, str | None]] = {}

    def add(transform: str, algorithm: str | None, *names: str) -> None:
        for name in names:
            found[name] = (transform, algorithm)

    add(ENCRYPTION, "NULL", "null")
    add(ENCRYPTION, "DES_CBC", "des")
    add(ENCRYPTION, "3DES_CBC", "3des")
    add(ENCRYPTION, "CAST_CBC", "cast128")
    add(ENCRYPTION, "CHACHA20_POLY1305", "chacha20poly1305", "chacha20poly1305compat")
    # The ICV lengths in bytes and bits; without one: 16 (not for Camellia).
    icvs = {"8": ("8", "64"), "12": ("12", "96"), "16": ("16", "128")}
    for cipher in ("aes", "camellia", "blowfish", "serpent", "twofish"):
        add(ENCRYPTION, f"{cipher.upper()}_CBC", cipher)
    for size in ("128", "192", "256"):
        for cipher in ("aes", "camellia", "blowfish", "serpent", "twofish"):
            add(ENCRYPTION, f"{cipher.upper()}_CBC", f"{cipher}{size}")
        for cipher in ("aes", "camellia"):
            add(ENCRYPTION, f"{cipher.upper()}_CTR", f"{cipher}{size}ctr")
            for icv, suffixes in icvs.items():
                add(
                    ENCRYPTION,
                    f"{cipher.upper()}_CCM_{icv}",
                    *(f"{cipher}{size}ccm{suffix}" for suffix in suffixes),
                )
        for icv, suffixes in icvs.items():
            add(
                ENCRYPTION,
                f"AES_GCM_{icv}",
                *(f"aes{size}gcm{suffix}" for suffix in suffixes),
            )
        add(ENCRYPTION, "AES_CCM_16", f"aes{size}ccm")
        add(ENCRYPTION, "AES_GCM_16", f"aes{size}gcm")
        add(ENCRYPTION, "NULL_AES_GMAC", f"aes{size}gmac")

    add(INTEGRITY, "HMAC_SHA1_96", "sha", "sha1")
    add(INTEGRITY, "HMAC_SHA1_160", "sha1_160")
    add(INTEGRITY, "HMAC_SHA2_256_128", "sha256", "sha2_256")
    add(INTEGRITY, "HMAC_SHA2_256_96", "sha256_96", "sha2_256_96")
    add(INTEGRITY, "HMAC_SHA2_384_192", "sha384", "sha2_384")
    add(INTEGRITY, "HMAC_SHA2_512_256", "sha512", "sha2_512")
    add(INTEGRITY, "HMAC_MD5_96", "md5")
    add(INTEGRITY, "HMAC_MD5_128", "md5_128")
    add(INTEGRITY, "AES_XCBC_96", "aesxcbc")
    add(INTEGRITY, "CAMELLIA_XCBC_96", "camelliaxcbc")
    add(INTEGRITY, "AES_CMAC_96", "aescmac")

    add(PRF, "PRF_HMAC_SHA1", "prfsha1")
    add(PRF, "PRF_HMAC_SHA2_256", "prfsha256")
    add(PRF, "PRF_HMAC_SHA2_384", "prfsha384")
    add(PRF, "PRF_HMAC_SHA2_512", "prfsha512")
    add(PRF, "PRF_HMAC_MD5", "prfmd5")
    add(PRF, "PRF_AES128_XCBC", "prfaesxcbc")
    add(PRF, "PRF_CAMELLIA128_XCBC", "prfcamelliaxcbc")
    add(PRF, "PRF_AES128_CMAC", "prfaescmac")

    add(KE, None, "none", "modpnone")
    add(KE, "MODP_NULL", "modpnull")
    for bits in ("768", "1024", "1536", "2048", "3072", "4096", "6144", "8192"):
        add(KE, f"MODP_{bits}", f"modp{bits}")
    for bits, sub in (("1024", "160"), ("2048", "224"), ("2048", "256")):
        add(KE, f"MODP_{bits}_{sub}", f"modp{bits}s{sub}")
    for bits in ("192", "224", "256", "384", "521"):
        add(KE, f"ECP_{bits}", f"ecp{bits}")
    for bits in ("224", "256", "384", "512"):
        add(KE, f"ECP_{bits}_BP", f"ecp{bits}bp")
    add(KE, "CURVE_25519", "curve25519", "x25519")
    add(KE, "CURVE_448", "curve448", "x448")
    add(KE, "GOST3410_256", "gost256")
    add(KE, "GOST3410_512", "gost512")
    for size in ("512", "768", "1024"):
        add(KE, f"ML_KEM_{size}", f"mlkem{size}")

    add(ESN, None, "noesn", "esn")
    return found


KEYWORDS = _keywords()
# A proposal of its own: charon's default proposals.
DEFAULT = "default"


def words(proposal: str, *, esp: bool) -> list[str]:
    """Return a proposal's keywords, as vpnc gives it to charon (no empty ones)."""
    proposal = proposal.replace("ipsec-" if esp else "ike-", "")
    return [word.strip() for word in proposal.split("-") if word.strip()]


def problem(proposal: str, *, esp: bool) -> str | None:  # noqa: PLR0911 (per check)
    """Return why charon refuses a proposal (IKE or ESP), or None.

    The checks of strongSwan's proposal_create_from_string.
    """
    if proposal.strip() == DEFAULT:
        return None
    transforms: dict[str, list[str | None]] = {kind: [] for kind in TYPES}
    for word in words(proposal, esp=esp):
        if word not in KEYWORDS:
            close = difflib.get_close_matches(word, KEYWORDS, n=3)
            hint = f" (did you mean {' or '.join(close)}?)" if close else ""
            return f"algorithm '{word}' isn't known{hint}"
        kind, algorithm = KEYWORDS[word]
        transforms[kind].append(algorithm)
    if not esp:
        prf = transforms[PRF] or [
            a for a in transforms[INTEGRITY] if a in PRF_FROM_INTEGRITY
        ]
        if not prf:
            return "an IKE proposal needs a PRF (e.g. prfsha384)"
        if not any(transforms[KE]):
            return "an IKE proposal needs a key exchange (e.g. ecp384)"
    encryption = transforms[ENCRYPTION]
    if not encryption:
        return "a proposal needs an encryption algorithm (e.g. aes256gcm16)"
    aead = [a in AEAD for a in encryption]
    if any(aead) and not all(aead):
        return "classic and combined-mode (AEAD) encryption can't be mixed"
    if not esp and not any(aead) and not transforms[INTEGRITY]:
        return "an IKE proposal with classic encryption needs an integrity algorithm"
    return None


def unavailable(
    proposal: str,
    algorithms: dict[str, set[str]],
    *,
    esp: bool,
) -> list[str]:
    """Return the keywords of algorithms charon doesn't have (a plugin missing).

    algorithms: by get-algorithms group (e.g. aead), the names charon has.
    """
    if proposal.strip() == DEFAULT:
        return []
    missing = []
    for word in words(proposal, esp=esp):
        kind, algorithm = KEYWORDS.get(word, (ESN, None))
        if algorithm is None or kind not in GROUPS:
            continue
        if not any(algorithm in algorithms.get(g, ()) for g in GROUPS[kind]):
            missing.append(word)
    return missing
