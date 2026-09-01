"""Small HTML parser for same-origin links and input forms."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urldefrag


@dataclass(frozen=True, slots=True)
class DiscoveredInput:
    name: str
    input_type: str = "text"
    default_value: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "type": self.input_type, "default_value": self.default_value}


@dataclass(frozen=True, slots=True)
class DiscoveredForm:
    url: str
    method: str
    action: str
    inputs: tuple[DiscoveredInput, ...]
    enctype: str = "application/x-www-form-urlencoded"

    def as_dict(self) -> dict[str, object]:
        return {"url": self.url, "method": self.method, "action": self.action, "enctype": self.enctype, "parameters": [item.as_dict() for item in self.inputs]}


class _Parser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.links: set[str] = set()
        self.forms: list[DiscoveredForm] = []
        self._form: dict[str, object] | None = None
        self._inputs: list[DiscoveredInput] = []
        self._textarea_name: str | None = None
        self._textarea_value: list[str] = []
        self._select_name: str | None = None
        self._select_value: str = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.casefold(): value or "" for key, value in attrs}
        if tag.casefold() == "a" and values.get("href"):
            absolute, _ = urldefrag(urljoin(self.page_url, values["href"]))
            self.links.add(absolute)
        elif tag.casefold() == "form":
            action = urljoin(self.page_url, values.get("action") or self.page_url)
            self._form = {"action": action, "method": (values.get("method") or "GET").upper(), "enctype": values.get("enctype") or "application/x-www-form-urlencoded"}
            self._inputs = []
        elif self._form is not None and tag.casefold() == "input" and values.get("name"):
            input_type = (values.get("type") or "text").casefold()
            self._inputs.append(DiscoveredInput(values["name"], input_type, values.get("value", "")))
        elif self._form is not None and tag.casefold() == "textarea" and values.get("name"):
            self._textarea_name, self._textarea_value = values["name"], []
        elif self._form is not None and tag.casefold() == "select" and values.get("name"):
            self._select_name, self._select_value = values["name"], ""
        elif self._select_name and tag.casefold() == "option" and not self._select_value:
            self._select_value = values.get("value", "")

    def handle_data(self, data: str) -> None:
        if self._textarea_name:
            self._textarea_value.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if tag == "textarea" and self._textarea_name:
            self._inputs.append(DiscoveredInput(self._textarea_name, "textarea", "".join(self._textarea_value)))
            self._textarea_name, self._textarea_value = None, []
        elif tag == "select" and self._select_name:
            self._inputs.append(DiscoveredInput(self._select_name, "select", self._select_value))
            self._select_name, self._select_value = None, ""
        elif tag == "form" and self._form is not None:
            self.forms.append(DiscoveredForm(url=self.page_url, method=str(self._form["method"]), action=str(self._form["action"]), inputs=tuple(self._inputs), enctype=str(self._form["enctype"])))
            self._form, self._inputs = None, []


def discover_html(html: str, page_url: str) -> tuple[list[str], list[DiscoveredForm]]:
    """Extract links and forms without executing JavaScript."""

    parser = _Parser(page_url)
    parser.feed(html)
    return sorted(parser.links), parser.forms


__all__ = ["DiscoveredForm", "DiscoveredInput", "discover_html"]
