import re, tldextract, requests
from html import unescape

CATEGORIES = [
    "Advertising",
    "AI Chatbots & Tools",
    "App Stores & System Updates",
    "Blogs",
    "Built-in Apps",
    "Collaboration",
    "Drugs & Alcohol",
    "Ecommerce",
    "Entertainment",
    "Gambling",
    "Games",
    "General / Education",
    "Health & Medicine",
    "Illegal, Malicious, or Hacking",
    "Religion",
    "Sexual Content",
    "Social Media",
    "Sports & Hobbies",
    "Streaming Services",
    "Weapons",
    "Uncategorized",
    "Allow only",
    "Global Block All",
]

KEYWORDS = {
    "AI Chatbots & Tools": ["chatgpt","openai","bard","claude","copilot","perplexity.ai","writesonic","midjourney"],
    "Social Media": ["tiktok","instagram","snapchat","facebook","x.com","twitter","reddit","discord","tumblr","be.real"],
    "Games": ["roblox","fortnite","minecraft","epicgames","leagueoflegends","steam","twitch","itch.io","riot games"],
    "Ecommerce": ["amazon","ebay","walmart","bestbuy","aliexpress","etsy","shopify","mercado libre","target.com"],
    "Streaming Services": ["netflix","spotify","hulu","vimeo","twitch","soundcloud","peacocktv","max.com","disneyplus"],
    "Sexual Content": ["porn","xxx","xvideos","redtube","xnxx","brazzers","onlyfans","camgirl","pornhub"],
    "Gambling": ["casino","sportsbook","bet","poker","slot","roulette","draftkings","fanduel"],
    "Illegal, Malicious, or Hacking": ["warez","piratebay","crack download","keygen","free movies streaming","sql injection","ddos","cheat engine"],
    "Drugs & Alcohol": ["buy weed","vape","nicotine","delta-8","kratom","bong","vodka","whiskey","winery","brewery"],
    "Collaboration": ["gmail","outlook","office 365","onedrive","teams","slack","zoom","google docs","google drive","meet.google"],
    "General / Education": ["wikipedia","news","encyclopedia","khan academy","nasa.gov",".edu"],
    "Sports & Hobbies": ["espn","nba","nfl","mlb","nhl","cars","boats","aircraft"],
    "App Stores & System Updates": ["play.google","apps.apple","microsoft store","firmware update","drivers download"],
    "Advertising": ["ads.txt","adserver","doubleclick","adchoices","advertising"],
    "Blogs": ["wordpress","blogger","wattpad","joomla","drupal","medium"],
    "Health & Medicine": ["patient portal","glucose","fitbit","apple health","pharmacy","telehealth"],
    "Religion": ["church","synagogue","mosque","bible study","quran","sermon"],
    "Weapons": ["knife","guns","rifle","ammo","silencer","tactical"],
    "Entertainment": ["tv shows","movies","anime","cartoons","jokes","memes"],
    "Built-in Apps": ["calculator","camera","clock","files app"],
    # ✅ Fixed keywords for Allow only (normalized)
    "Allow only": ["canvas", "k12", "instructure.com"],

}

def _fetch_html(url: str, timeout=3):
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent":"Mozilla/5.0"})
        if r.ok and "text" in r.headers.get("Content-Type",""):
            return r.text
    except Exception:
        return ""
    return ""

def _textify(html: str):
    if not html: return ""
    txt = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.I)
    txt = re.sub(r"<style[\s\S]*?</style>", " ", txt, flags=re.I)
    txt = re.sub(r"<[^>]+>", " ", txt)
    txt = unescape(txt)
    txt = re.sub(r"\s+", " ", txt).strip().lower()
    return txt

def classify(url: str, html: str = None):
    """
    Returns dict: {category: str, confidence: float}
    """
    if not (url or "").startswith(("http://","https://")):
        url = "https://" + (url or "")
    ext = tldextract.extract(url)
    domain = ".".join([p for p in [ext.domain, ext.suffix] if p])
    host = ".".join([p for p in [ext.subdomain, ext.domain, ext.suffix] if p if p])

    tokens = [url.lower(), host.lower(), domain.lower()]
    body = _textify(html) if html else _textify(_fetch_html(url))
    if body:
        tokens.append(body)

    scores = {c: 0 for c in CATEGORIES}
    for cat, kws in KEYWORDS.items():
        for kw in kws:
            pat = kw.lower()
            for t in tokens:
                if pat in t:
                    scores[cat] += 1

    # Special-case rules
    if any(s in domain for s in ["edu",".edu"]): scores["General / Education"] += 3
    if any(s in url for s in ["wp-login","/wp-content/"]): scores["Blogs"] += 1

    # ✅ Prioritize Allow only
    if scores["Allow only"] > 0:
        best_cat = "Allow only"
    else:
        best_cat = max(scores, key=lambda c: scores[c])
        if scores[best_cat] == 0:
            best_cat = "Uncategorized"

    total = sum(scores.values()) or 1
    conf = scores[best_cat] / total
    return {"category": best_cat, "confidence": float(conf), "domain": domain, "host": host}

