import re

def detect_language(text: str) -> str:
    """
    Detects whether input text is English ('en'), Khmer ('km'), or Mixed Khmer-English ('km-en').
    """
    if not text or not text.strip():
        return "en"

    # Khmer Unicode block: \u1780-\u17FF and symbols \u19E0-\u19FF
    khmer_pattern = re.compile(r'[\u1780-\u17FF\u19E0-\u19FF]')
    latin_pattern = re.compile(r'[a-zA-Z]')

    khmer_matches = khmer_pattern.findall(text)
    latin_matches = latin_pattern.findall(text)

    khmer_count = len(khmer_matches)
    latin_count = len(latin_matches)

    if khmer_count > 0 and latin_count > 0:
        # Check if both have noticeable presence
        ratio = min(khmer_count, latin_count) / max(khmer_count, latin_count)
        if ratio >= 0.15 or (khmer_count >= 5 and latin_count >= 5):
            return "km-en"

    if khmer_count > latin_count:
        return "km"
    
    return "en"
