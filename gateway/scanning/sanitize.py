import unicodedata
import re

# Homoglyph map: visually similar chars → ASCII equivalent
_HOMOGLYPHS = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u0501': 'd', '\u051b': 'q', '\u0455': 's', '\u04bb': 'h',
    '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041a': 'K',
    '\u041c': 'M', '\u041d': 'H', '\u041e': 'O', '\u0420': 'P',
    '\u0421': 'C', '\u0422': 'T', '\u0425': 'X',
    '\uff41': 'a', '\uff42': 'b', '\uff43': 'c', '\uff44': 'd',
    '\uff45': 'e', '\uff46': 'f', '\uff47': 'g', '\uff48': 'h',
    '\uff49': 'i', '\uff4a': 'j', '\uff4b': 'k', '\uff4c': 'l',
    '\uff4d': 'm', '\uff4e': 'n', '\uff4f': 'o', '\uff50': 'p',
    '\u200b': '', '\u200c': '', '\u200d': '', '\ufeff': '',  # zero-width
    '\u00a0': ' ',  # non-breaking space
}


def normalize_text(text: str) -> str:
    """Normalize unicode to catch homoglyph and encoding bypass attacks."""
    # NFKC normalization (fullwidth → ASCII, compatibility decomposition)
    text = unicodedata.normalize("NFKC", text)
    # Replace known homoglyphs
    text = ''.join(_HOMOGLYPHS.get(c, c) for c in text)
    # Collapse multiple spaces/whitespace into single space
    text = re.sub(r'\s+', ' ', text)
    return text
