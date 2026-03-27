"""Extract actionable indicators (URLs, domains, IPs, attachments) from raw email content."""

import email
import email.policy
import re
from html.parser import HTMLParser


# Regex patterns
URL_RE = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')


def _is_valid_ip(ip: str, context: str = "") -> bool:
    """Filter out false-positive IPs (date fragments, etc.).

    Uses octet range validation plus contextual checks. Date-like fragments
    (e.g., 03.12.05.15 from timestamps) are rejected by checking whether the
    IP appears inside a Received header timestamp region or other date context.
    """
    octets = ip.split(".")
    if len(octets) != 4:
        return False
    vals = []
    for octet in octets:
        val = int(octet)
        if val > 255:
            return False
        vals.append(val)
    # First octet 0 is not routable
    if vals[0] == 0:
        return False
    # Check if this "IP" is actually embedded in a date/time string
    # Common pattern: "03.12.05.15" from "2026.03.12.05.15.36" or similar timestamp fragments
    # Heuristic: if the IP appears directly adjacent to date-like context, reject it
    if context:
        # Find position of IP in context and check surrounding chars
        idx = context.find(ip)
        if idx >= 0:
            # Check if preceded or followed by more digits/dots (part of a longer number sequence)
            before = context[max(0, idx - 3):idx]
            after = context[idx + len(ip):idx + len(ip) + 3]
            if re.search(r'\d[.\-/]$', before) or re.search(r'^[.\-/]\d', after):
                return False
    return True


class _LinkExtractor(HTMLParser):
    """Extract href/display-text pairs from HTML."""

    def __init__(self):
        super().__init__()
        self.links: list[dict] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            href = dict(attrs).get("href", "")
            self._current_href = href
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_href is not None:
            display = "".join(self._current_text).strip()
            self.links.append({"href": self._current_href, "display_text": display})
            self._current_href = None
            self._current_text = []


class _ImageDetector(HTMLParser):
    """Detect tracking pixels (1x1 or hidden images)."""

    def __init__(self):
        super().__init__()
        self.images: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "img":
            attr_dict = dict(attrs)
            self.images.append(attr_dict)


def _is_tracking_pixel(img_attrs: dict) -> bool:
    """Check if an image looks like a tracking pixel."""
    width = img_attrs.get("width", "")
    height = img_attrs.get("height", "")
    style = img_attrs.get("style", "")

    if width in ("1", "0") or height in ("1", "0"):
        return True
    if "display:none" in style.replace(" ", "") or "visibility:hidden" in style.replace(" ", ""):
        return True
    return False


def extract_urls_from_text(text: str) -> list[str]:
    """Extract all URLs from plain text."""
    return URL_RE.findall(text)


def extract_links_from_html(html: str) -> list[dict]:
    """Extract href/display-text pairs from HTML, flagging mismatches."""
    parser = _LinkExtractor()
    parser.feed(html)
    return parser.links


def detect_tracking_pixels(html: str) -> bool:
    """Check if HTML contains likely tracking pixels."""
    detector = _ImageDetector()
    detector.feed(html)
    return any(_is_tracking_pixel(img) for img in detector.images)


def find_url_mismatches(links: list[dict]) -> list[dict]:
    """Find links where the display text looks like a URL but differs from the href."""
    mismatches = []
    for link in links:
        display = link["display_text"]
        href = link["href"]
        # Only flag if display text looks like a URL
        if URL_RE.match(display) or DOMAIN_RE.match(display):
            # Normalize for comparison
            display_clean = display.rstrip("/").lower()
            href_clean = href.rstrip("/").lower()
            if display_clean not in href_clean and href_clean not in display_clean:
                mismatches.append({
                    "href": href,
                    "display_text": display,
                    "reason": "Display text looks like a URL/domain but differs from href",
                })
    return mismatches


def parse_email_structure(raw_email: str) -> dict:
    """Parse a raw email and extract all actionable indicators."""
    msg = email.message_from_string(raw_email, policy=email.policy.default)

    all_urls: list[str] = []
    html_parts: list[str] = []
    text_parts: list[str] = []
    html_links: list[dict] = []
    has_html = False
    has_tracking_pixels = False

    # Extract from headers
    header_text = "\n".join(f"{k}: {v}" for k, v in msg.items())
    header_ips = [ip for ip in IP_RE.findall(header_text) if _is_valid_ip(ip, header_text)]

    # Walk MIME parts
    attachments = []
    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", ""))

        if "attachment" in disposition:
            attachments.append({
                "filename": part.get_filename() or "unknown",
                "content_type": content_type,
            })
            continue

        if content_type == "text/plain":
            payload = part.get_content()
            if isinstance(payload, str):
                text_parts.append(payload)
                all_urls.extend(extract_urls_from_text(payload))

        elif content_type == "text/html":
            has_html = True
            payload = part.get_content()
            if isinstance(payload, str):
                html_parts.append(payload)
                all_urls.extend(extract_urls_from_text(payload))
                links = extract_links_from_html(payload)
                html_links.extend(links)
                # Also grab href URLs
                for link in links:
                    if link["href"].startswith("http"):
                        all_urls.append(link["href"])
                if detect_tracking_pixels(payload):
                    has_tracking_pixels = True

    # Deduplicate URLs
    seen = set()
    unique_urls = []
    for url in all_urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)

    # Extract domains from URLs
    domains = set()
    for url in unique_urls:
        match = re.search(r'https?://([^/:]+)', url)
        if match:
            domains.add(match.group(1).lower())

    # Sender domain
    from_addr = msg.get("From", "")
    sender_domain = ""
    email_match = re.search(r'[\w.+-]+@([\w.-]+)', from_addr)
    if email_match:
        sender_domain = email_match.group(1).lower()

    # Body IPs
    body_text = "\n".join(text_parts + html_parts)
    body_ips = [ip for ip in IP_RE.findall(body_text) if _is_valid_ip(ip, body_text)]

    # URL mismatches
    url_mismatches = find_url_mismatches(html_links)

    return {
        "urls": unique_urls,
        "url_mismatches": url_mismatches,
        "domains": sorted(domains),
        "sender_domain": sender_domain,
        "ip_addresses": sorted(set(header_ips + body_ips)),
        "attachments": attachments,
        "has_html": has_html,
        "has_tracking_pixels": has_tracking_pixels,
    }
