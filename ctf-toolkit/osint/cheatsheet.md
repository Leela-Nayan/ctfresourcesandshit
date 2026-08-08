# osint cheatsheet

## approach
```
1. Start with what you have (username, email, image, domain, IP)
2. Pivot: each finding -> leads to more findings
3. Document everything — timestamps, URLs, screenshots
```

---

## username / person

### username search
| Tool | URL | What |
|------|-----|------|
| **Namechk** | https://namechk.com/ | Check username across 100+ sites |
| **Sherlock** | `sherlock username` | CLI: https://github.com/sherlock-project/sherlock |
| **WhatsMyName** | https://whatsmyname.app/ | Username enumeration |
| **Maigret** | `maigret username` | Extended sherlock: https://github.com/soxoj/maigret |

### email investigation
```bash
# Check if email is in data breaches:
# https://haveibeenpwned.com/

# Email -> social accounts:
# https://epieos.com/

# Email header analysis (for phishing challenges):
# https://mxtoolbox.com/EmailHeaders.aspx
```

---

## domain / website

### whois
```bash
whois example.com                            # domain registration info
whois 1.2.3.4                                # IP registration info
```

### dns
```bash
dig example.com                              # A record
dig example.com MX                           # mail servers
dig example.com TXT                          # TXT records (SPF, DKIM, flags!)
dig example.com ANY                          # all records
dig @8.8.8.8 example.com                     # specific DNS server
host example.com                             # quick lookup
nslookup example.com                         # alternative
```

### subdomains
```bash
# Sublist3r
sublist3r -d example.com

# crt.sh (certificate transparency)
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq '.[].name_value' | sort -u

# Online: https://crt.sh/
```

### web archive
```
https://web.archive.org/web/*/example.com
# Check older versions of the site for removed content, old flags
```

### tech detection
```bash
# whatweb
whatweb http://example.com

# Wappalyzer (browser extension)
# BuiltWith: https://builtwith.com/
```

---

## geolocation

### image geolocation
```bash
exiftool image.jpg                           # GPS coordinates in metadata
# If no GPS -> visual clues:
# Google Maps / Google Street View
# https://www.google.com/maps
# GeoGuessr techniques: road signs, language, vegetation, sun position
```

### ip geolocation
```bash
curl ipinfo.io/1.2.3.4                       # IP location
# https://ipinfo.io/
# https://www.iplocation.net/
```

### coords to address
```
# Google Maps: paste coordinates directly
# Format: 12.345678, 67.891234
```

---

## image search

### reverse image search
| Service | URL |
|---------|-----|
| Google Images | https://images.google.com/ (click camera icon) |
| TinEye | https://tineye.com/ |
| Yandex | https://yandex.com/images/ (best for faces/locations) |
| Bing | https://www.bing.com/images/ |

### image metadata
```bash
exiftool image.jpg                           # ALL metadata
exiftool -GPS* image.jpg                     # GPS only
exiftool -Model image.jpg                    # camera model
exiftool -DateTimeOriginal image.jpg         # when taken
```

---

## social media

### twitter
```
# Advanced search: https://twitter.com/search-advanced
# Search operators:
from:username                                # from specific user
to:username                                  # replies to user
"exact phrase"                               # exact match
since:2024-01-01 until:2024-12-31           # date range
filter:images                                # only with images
```

### github
```
# Search: https://github.com/search
# Dorks:
"password" filename:.env                     # secrets in .env files
"api_key" user:targetuser                    # API keys from user
"flag{" user:targetuser                      # flags in repos
org:targetorg                                # all repos from org
```

### google dorks
```
site:example.com                             # search within site
"index of" site:example.com                  # directory listings
filetype:pdf site:example.com                # specific file types
inurl:admin site:example.com                 # admin pages
intitle:"index of" "password"                # password files
cache:example.com/page                       # cached version
```

---

## tools summary

| Category | Tool | URL/Command |
|----------|------|------------|
| Username | Sherlock | `sherlock username` |
| Email | HIBP | https://haveibeenpwned.com/ |
| Domain | WHOIS | `whois domain.com` |
| Subdomains | crt.sh | https://crt.sh/ |
| Web history | Wayback | https://web.archive.org/ |
| Image search | TinEye/Yandex | https://tineye.com/ |
| Image metadata | exiftool | `exiftool image.jpg` |
| IP lookup | ipinfo | https://ipinfo.io/ |
| Google dorking | Google | Advanced search operators |

## decision tree
```
OSINT challenge?
├- Given username -> Sherlock -> social media profiles -> pivot
├- Given email -> HIBP -> epieos -> linked accounts
├- Given image -> exiftool GPS -> reverse image search -> geolocation
├- Given domain -> WHOIS -> DNS -> subdomains -> web archive
├- Given IP -> ipinfo -> WHOIS -> reverse DNS -> Shodan
└- Given coordinates -> Google Maps -> Street View -> identify location
```
