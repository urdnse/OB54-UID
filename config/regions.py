# ╔══════════════════════════════════════════════════════════════╗
# ║         Script Kittens — Free Fire UID Bypass               ║
# ║  Developers  :  1shot  &  Zen                               ║
# ║  Discord     :  discord.gg/8C3hw3Cyb2                       ║
# ║  Join for more projects, tools & community support!         ║
# ╚══════════════════════════════════════════════════════════════╝

# Region configuration
REGION_LANG = {
    "ME": "ar",    # Middle East
    "IND": "hi",   # India
    "ID": "id",    # Indonesia
    "VN": "vi",    # Vietnam
    "TH": "th",    # Thailand
    "BD": "bn",    # Bangladesh
    "PK": "ur",    # Pakistan
    "TW": "zh",    # Taiwan
    "EU": "en",    # Europe
    "CIS": "ru",   # Commonwealth of Independent States (mostly Russia, ex-USSR)
    "NA": "en",    # North America
    "SAC": "es",   # South America (Spanish-speaking)
    "BR": "pt"     # Brazil
}

REGION_URLS = {
    "IND": "https://client.ind.freefiremobile.com/",
    "ID": "https://clientbp.ggblueshark.com/",
    "BR": "https://client.us.freefiremobile.com/",
    "ME": "https://clientbp.common.ggbluefox.com/",
    "VN": "https://clientbp.ggblueshark.com/",
    "TH": "https://clientbp.common.ggbluefox.com/",
    "CIS": "https://clientbp.ggblueshark.com/",
    "BD": "https://clientbp.ggblueshark.com/",
    "PK": "https://clientbp.ggblueshark.com/",
    "SG": "https://clientbp.ggblueshark.com/",
    "NA": "https://client.us.freefiremobile.com/",
    "SAC": "https://client.us.freefiremobile.com/",
    "EU": "https://clientbp.ggblueshark.com/",
    "TW": "https://clientbp.ggblueshark.com/"
}

def get_region(language_code: str) -> str:
    """Return language code for a given region"""
    return REGION_LANG.get(language_code)

def get_region_url(region_code: str) -> str:
    """Return URL for a given region code"""
    return REGION_URLS.get(region_code, None)

def LoginUrl(server: str) -> str:
    if server == "IND":
        return "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    elif server == "ID":
        return "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    elif server == "BR":
        return "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    elif server == "ME":
        return "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    elif server == "VN":
        return "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    elif server == "TH":
        return "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
