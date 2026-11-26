"""Unicode normalization, Devanagari-Latin transliteration, and phonetic keys."""

from __future__ import annotations

import re
import unicodedata

# Devanagari digits U+0966..U+096F -> ASCII 0..9
_DEVA_DIGIT_TRANS = str.maketrans("०१२३४५६७८९", "0123456789")

# Common Cyrillic/Greek homoglyphs to Latin equivalents
_HOMOGLYPH_TRANS = str.maketrans({
    "\u0410": "A", "\u0430": "a", "\u0412": "B", "\u0435": "e", "\u0415": "E",
    "\u041a": "K", "\u043a": "k", "\u041c": "M", "\u041d": "H", "\u041e": "O",
    "\u043e": "o", "\u0420": "P", "\u0440": "p", "\u0421": "C", "\u0441": "c",
    "\u0422": "T", "\u0443": "y", "\u0425": "X", "\u0445": "x", "\u0456": "i",
    "\u0406": "I", "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z",
    "\u0397": "H", "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N",
    "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
})

_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\ufeff]")
_DEVANAGARI_CHAR_RE = re.compile(r"[\u0900-\u097f]")

# Devanagari -> Latin transliteration tables (with nukta support)
_DEVA_VOWELS = {
    "अ": "a", "आ": "aa", "इ": "i", "ई": "ee", "उ": "u", "ऊ": "oo",
    "ऋ": "ri", "ए": "e", "ऐ": "ai", "ओ": "o", "औ": "au",
    "अं": "an", "अः": "ah", "ऑ": "o",
}

_DEVA_MATRAS = {
    "ा": "a", "ि": "i", "ी": "ee", "ु": "u", "ू": "oo",
    "ृ": "ri", "े": "e", "ै": "ai", "ो": "o", "ौ": "au",
    "ॅ": "e", "ॉ": "o", "्": "",
}

_DEVA_CONSONANTS = {
    "क": "k", "ख": "kh", "ग": "g", "घ": "gh", "ङ": "ng",
    "च": "ch", "छ": "chh", "ज": "j", "झ": "jh", "ञ": "ny",
    "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n",
    "त": "t", "थ": "th", "द": "d", "ध": "dh", "न": "n",
    "प": "p", "फ": "ph", "ब": "b", "भ": "bh", "म": "m",
    "य": "y", "र": "r", "ल": "l", "व": "v", "श": "sh",
    "ष": "sh", "स": "s", "ह": "h",
    "क़": "q", "ख़": "kh", "ग़": "g", "ज़": "z", "ड़": "r", "ढ़": "rh", "फ़": "f",
    "य़": "y", "ऱ": "r", "ळ": "l",
}

_DEVA_NASALS = {"ं": "n", "ँ": "n", "ः": "h"}


def normalize_digits(text: str) -> str:
    """Convert Devanagari digits to ASCII digits while preserving string structure."""
    return text.translate(_DEVA_DIGIT_TRANS)


def normalize_surface(text: str) -> str:
    """Normalize NFKC, strip zero-width chars, fold homoglyphs, convert Indic digits."""
    s = unicodedata.normalize("NFKC", text)
    s = _ZERO_WIDTH_RE.sub("", s)
    s = s.translate(_HOMOGLYPH_TRANS)
    s = s.translate(_DEVA_DIGIT_TRANS)
    return s


def strip_diacritics(text: str) -> str:
    """Remove combining Latin accents while keeping base characters."""
    decomposed = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")


def has_devanagari(text: str) -> bool:
    """Return True if text contains any Devanagari codepoint."""
    return bool(_DEVANAGARI_CHAR_RE.search(text))


def devanagari_to_latin(text: str) -> str:
    """Transliterate Devanagari words into readable Indian-English Latin approximations."""
    s = unicodedata.normalize("NFC", normalize_surface(text))
    # Handle precomposed or decomposed nukta pairs uniformly
    out: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        # Check consonant + nukta (\u093c)
        if i + 1 < n and s[i + 1] == "\u093c" and (ch + "\u093c") in _DEVA_CONSONANTS:
            pair = ch + "\u093c"
            i += 2
            cons = _DEVA_CONSONANTS[pair]
            out_chunk, i = _consume_vowel_after_consonant(s, i, n, cons)
            out.append(out_chunk)
            continue
        if ch in _DEVA_CONSONANTS:
            cons = _DEVA_CONSONANTS[ch]
            i += 1
            out_chunk, i = _consume_vowel_after_consonant(s, i, n, cons)
            out.append(out_chunk)
            continue
        if ch in _DEVA_VOWELS:
            out.append(_DEVA_VOWELS[ch])
            i += 1
            continue
        if ch in _DEVA_NASALS:
            out.append(_DEVA_NASALS[ch])
            i += 1
            continue
        if ch in _DEVA_MATRAS:
            out.append(_DEVA_MATRAS[ch])
            i += 1
            continue
        if ch in ("।", "॥"):
            out.append(".")
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _consume_vowel_after_consonant(s: str, i: int, n: int, cons: str) -> tuple[str, int]:
    """Attach matra or inherent schwa to a Devanagari consonant (with word-final schwa drop)."""
    if i < n and s[i] == "्":  # virama (halant): no inherent 'a'
        return cons, i + 1
    if i < n and s[i] in _DEVA_MATRAS:
        return cons + _DEVA_MATRAS[s[i]], i + 1
    # Check if next char is end of word or non-Devanagari -> drop final schwa (e.g. शाहिद -> shahid)
    if i >= n or not (_DEVANAGARI_CHAR_RE.match(s[i]) or s[i] in _DEVA_NASALS):
        return cons, i
    # If next char is anusvara at end of word, keep 'a' + nasal
    return cons + "a", i


_ABBREV_MAP = {
    "mohd": "mohammad",
    "md": "mohammad",
    "mohammad": "mohammad",
    "muhammad": "mohammad",
    "mahammad": "mohammad",
    "smt": "",
    "shri": "",
    "kumari": "",
    "km": "",
    "mr": "",
    "mrs": "",
    "ms": "",
    "ji": "",
    "sahab": "",
    "saheb": "",
    "bhaiya": "",
    "behenji": "",
    "didi": "",
    "babu": "",
    "amma": "",
}


def canonical_latin_name(name: str) -> str:
    """Normalize English/Devanagari/Hinglish name into lowercase canonical ASCII tokens."""
    s = normalize_surface(name)
    if has_devanagari(s):
        s = devanagari_to_latin(s)
    s = strip_diacritics(s).lower()
    s = re.sub(r"[^a-z\s]", " ", s)
    tokens = []
    for tok in s.split():
        mapped = _ABBREV_MAP.get(tok, tok)
        if mapped:
            tokens.append(mapped)
    return " ".join(tokens)


def phonetic_token_key(token: str) -> str:
    """Reduce an Indian Latin/transliterated name token to a vowel-tolerant phonetic skeleton.

    Bridges spelling variants such as:
    Rina/Reena, Harish/Hareesh, Fatma/Fatima, Shanthi/Shanti, Chouhan/Chauhan,
    Choudhary/Chaudhary, Zainab/Zenab, Mohammad/Mohd/Md, Sunita/Suneeta, Qureshi/Kureshi.
    """
    t = token.lower().strip()
    if not t:
        return ""
    if t in _ABBREV_MAP and _ABBREV_MAP[t]:
        t = _ABBREV_MAP[t]
    # Normalize common Indian digraphs and aspirated variants
    replacements = (
        ("ph", "f"),
        ("v", "w"),
        ("q", "k"),
        ("z", "j"),
        ("sh", "s"),
        ("chh", "ch"),
        ("th", "t"),
        ("dh", "d"),
        ("bh", "b"),
        ("gh", "g"),
        ("kh", "k"),
        ("jh", "j"),
        ("ee", "i"),
        ("oo", "u"),
        ("aa", "a"),
        ("ae", "e"),
        ("ai", "e"),
        ("au", "o"),
        ("ou", "o"),
        ("ey", "e"),
        ("ya", "y"),
    )
    for src, dst in replacements:
        t = t.replace(src, dst)
    # Collapse repeated consonants and strip non-initial short vowels (a, e, i, o, u)
    dedup: list[str] = []
    for idx, ch in enumerate(t):
        if idx > 0 and ch in "aeiou":
            continue
        if not dedup or dedup[-1] != ch:
            dedup.append(ch)
    return "".join(dedup)


def phonetic_name_key(name: str) -> str:
    """Compute a sorted/ordered phonetic key across tokens of a name."""
    canon = canonical_latin_name(name)
    parts = [phonetic_token_key(p) for p in canon.split() if len(p) > 0]
    return " ".join(p for p in parts if p)
