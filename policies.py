"""Public lab policies and the matching notice presented during admission."""

from hashlib import sha256
from html import escape
import json


EFFECTIVE_DATE = "2026-11-23"
DATE_LABEL = "November 23, 2026"
# The same document can be read inside an admitted visit, where provider-injected
# decoder scripts do not run. Keep the published reporting link usable in both views.
CONTACT = '<!--email_off--><a href="mailto:ngioanni@uw.edu">ngioanni@uw.edu</a><!--/email_off-->'
CF_PRIVACY = '<a href="https://www.cloudflare.com/privacypolicy/">Cloudflare Privacy Policy</a>'
CF_TURNSTILE = '<a href="https://www.cloudflare.com/turnstile-privacy-policy/">Turnstile Privacy Addendum</a>'
CF_COOKIES = '<a href="https://developers.cloudflare.com/fundamentals/reference/policies-compliances/cloudflare-cookies/">Cloudflare cookie reference</a>'
CF_RECOVERY = '<a href="https://developers.cloudflare.com/d1/reference/time-travel/">Cloudflare database recovery documentation</a>'
GH_PRIVACY = '<a href="https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement">GitHub General Privacy Statement</a>'
GH_TERMS = '<a href="https://docs.github.com/en/site-policy/github-terms/github-terms-of-service">GitHub Terms of Service</a>'
GH_AUP = '<a href="https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies">GitHub Acceptable Use Policies</a>'

NOTICE_INTRO = "Nicolas Gioanni operates this independent security research site. Access to the research is monitored."
NOTICE_SECTIONS = (
    ("Permitted use", "You may read and cite the published work and reproduce documented experiments on systems you control. Testing the live lab or a connected service requires separate written authorization."),
    ("Security monitoring", 'Cloudflare processes connection and browser signals before you accept. The lab logs the time, IP address, estimated country, route category, access decision, shortened browser user-agent and, on acceptance, the policy revision. Active lab logs have a seven-day retention policy. <a href="/privacy">Privacy Policy</a>'),
    ("Browser session", 'An essential cookie connects this notice to the browser check for up to ten minutes. Accepting or declining clears it. Navigating inside the admitted page reuses that visit. Opening a fresh research page requires another check. A theme choice is saved in your browser. <a href="/cookies">Cookies &amp; Browser Storage</a>'),
)
NOTICE_DECLINE = "Select Decline to leave the research closed. You can read the policies independently."
NOTICE_AGREEMENT = 'By selecting Accept and enter, you agree to the <a href="/terms">Terms &amp; Conditions</a> and acknowledge the <a href="/access-notice">Access Notice</a>.'


def notice_html(*, dialog=True):
    """Render the same visitor-facing text in the popup and on its own page."""
    intro = ' class="project-skill-dialog__summary" id="notice-intro"' if dialog else ""
    section = ' class="project-skill-dialog__details"' if dialog else ""
    heading = ' class="project-skill-dialog__details-title"' if dialog else ""
    parts = [f"<p{intro}>{NOTICE_INTRO}</p>"]
    for title, copy in NOTICE_SECTIONS:
        parts.append(f"<section{section}><h2{heading}>{title}</h2><p>{copy}</p></section>")
    agreement = "" if dialog else f"<p>{NOTICE_AGREEMENT}</p>"
    parts.append(f"<section{section}><h2{heading}>Your choice</h2><p>{NOTICE_DECLINE}</p>{agreement}</section>")
    return "\n".join(parts)


# The section bodies below are authored HTML. No request or visitor data enters this template.
POLICIES = {
    "/access-notice": ("Access Notice", "The notice presented before you enter the research lab.", ()),
    "/privacy": ("Privacy Policy", "What the lab records about a visit, who processes it, and how to make a privacy request.", (
        ("Who handles your data",
         "Nicolas Gioanni operates this independent lab and determines how its admission records are used. This policy covers the lab hostname and messages you choose to send about it. You can read the policies without an account or an admission check."),
        ("Information recorded at entry",
         "When your browser opens verification, the lab starts recording admission events. Each event can include the time, the connecting IP address, the country estimated from that address, a route category such as verification or acceptance, the access decision, and a shortened user-agent string supplied by your browser. A successful acceptance also records the revision of the policies presented to you.",
         "An IP address can be shared by several visitors, and a country estimate can reflect a VPN or a network gateway. The lab uses these fields to investigate repeated failures and service abuse. It uses the revision to determine which terms a visitor accepted. Admission records contain neither a visitor account nor a verified identity."),
        ("Hosting and browser verification",
         f"Cloudflare receives requests to this hostname, delivers pages, and processes security events. Its Turnstile service evaluates browser and connection signals when you open verification, before you make an admission choice. Cloudflare processes signals on behalf of the lab to protect this site and independently uses signals to improve its bot detection. Cloudflare describes its processing locations, safeguards, and privacy contacts in its own notices. {CF_PRIVACY} · {CF_TURNSTILE}"),
        ("Who can receive information",
         "The operator can inspect admission records through Cloudflare to maintain the service, diagnose failures, and investigate misuse. The lab may disclose relevant information when required by law. The lab uses no advertising trackers and does not sell admission records or publish them as research data.",
         f"Following a research repository link takes you to GitHub. GitHub receives that request and applies its own account, device, and privacy practices. {GH_PRIVACY}"),
        ("Retention and deletion",
         f"The lab applies a seven-day retention period to its active admission log. Routine cleanup removes expired records, and volume limits can remove older entries sooner. Temporary admission state expires separately. Cloudflare's security records and recovery copies follow its own processes and schedules. Deleting an active row does not immediately erase every provider recovery copy. {CF_RECOVERY}"),
        ("Correspondence and privacy requests",
         f"If you email the operator, your email service and the recipient's mail service process your message. The operator uses your address and the information you provide to handle the request. The admission log's seven-day period applies only to that log. Contact {CONTACT}.",
         "To ask about a visit, give its approximate date, time and time zone, and describe what you are requesting. Avoid sending identity documents, credentials, or private logs. The operator may need limited additional information to match a request and protect other visitors' records. An expired record or a shared connection can prevent a reliable match.",
         "Depending on applicable law, you may have rights to access, correct or delete personal data, object to processing, or complain to a privacy regulator. Where a legitimate-interest basis applies, the lab's interest is in protecting access and investigating service abuse. Accepting the site's terms preserves rights that applicable law makes mandatory."),
    )),
    "/cookies": ("Cookies & Browser Storage", "What the lab stores in your browser and how your settings affect a visit.", (
        ("The admission cookie",
         "After a successful browser check, the lab sets a temporary, host-only session cookie. It connects the pending notice with the request that accepts or declines it. The browser sends it only over HTTPS and page scripts cannot read it. The matching pending notice expires on the server after ten minutes.",
         "When you accept or decline, the lab asks the browser to clear the cookie. If you leave without choosing, the browser may retain it according to its session settings. Once the pending notice expires, that cookie cannot complete it."),
        ("Navigation during an admitted visit",
         "The current document holds the admitted research in memory. You can move between its research views or read a policy and return without making another admission request. Reloading a research page, opening it in a new tab, or restoring a document after leaving requires a fresh check. The lab does not store an admission ticket in browser local storage."),
        ("Theme preference",
         "Choosing System, Light, My mode, or Dark saves a preference in this lab hostname's local storage when your browser permits it. System follows your device setting. You can change your selection at any time or clear site data to remove it. The lab uses this value only to display your chosen theme."),
        ("Cloudflare protection",
         f"Cloudflare may use security cookies or browser signals to distinguish legitimate requests from automated abuse. Which cookies appear depends on the protection Cloudflare applies to a request. Its documentation identifies their purposes and lifetimes. {CF_COOKIES} · {CF_TURNSTILE}"),
        ("Your browser controls",
         'You can inspect or delete cookies and local storage in your browser’s site-data settings. Blocking first-party cookies or the browser verification script can prevent research admission. You can still open the <a href="/access-notice">Access Notice</a> and other policy documents directly. The <a href="/privacy">Privacy Policy</a> explains what is recorded on the server.'),
    )),
    "/terms": ("Terms & Conditions", "The conditions for reading, citing, and reproducing the lab’s published work.", (
        ("Operator and agreement",
         'Nicolas Gioanni publishes this independent research portfolio in a personal capacity. Selecting Accept and enter records agreement to these Terms and acknowledgement of the <a href="/access-notice">Access Notice</a> for that admission. If you do not agree, choose Decline. Public policy pages remain available to read.'),
        ("Permission to use the research",
         "You may read the research, link to it, cite findings accurately, and reproduce documented experiments using appropriately licensed materials on systems you control or have permission to use. When citing a result, identify the study, its version or date, and its experimental scope. Identify your own modifications and measurements separately.",
         "Respect the license attached to each item you reuse. The portfolio-derived interface carries an MIT license and the bundled Space Grotesk font carries the SIL Open Font License. The respective notices govern those materials. Other site content remains subject to its own notices and applicable law. " +
         '<a href="/assets/portfolio-LICENSE.txt">Interface license</a> · <a href="/assets/OFL.txt">Font license</a>'),
        ("Conditions of access",
         'Access permits reading the published material. Testing a live endpoint, interfering with availability, evading admission controls, or seeking nonpublic information requires separate, express written authorization covering the intended activity. The operator may refuse, suspend, or revoke access to protect the service or respond to misuse. <a href="/security">Security &amp; Responsible Disclosure</a>'),
        ("Evidence, accuracy and reliance",
         "A finding applies to the fixture, tool version, and procedure documented in its study. Validate any result in your own authorized environment before relying on it in a security decision. Research plans may change. No page certifies a product, promises a security outcome, or represents a government, university, employer, or service provider."),
        ("Availability and liability",
         "The operator provides the site and research as available and may revise or withdraw material. To the extent permitted by applicable law, the operator disclaims warranties of fitness for a particular purpose and excludes liability for indirect or consequential losses arising from use of the research. Mandatory rights, remedies, and liabilities remain in effect."),
        ("External services and changes",
         f"GitHub hosts the public research repository. Activity on GitHub is subject to its own terms and acceptable-use rules. {GH_TERMS} · {GH_AUP}",
         f"The effective date identifies this edition. The admission dialog presents the terms in force when you enter, and a change during a pending admission requires review of the updated notice. For questions about permissions, attribution, or a correction, email {CONTACT}."),
    )),
    "/security": ("Security & Responsible Disclosure", "Permitted activity on the live lab and how to report an issue privately.", (
        ("Authorized activity",
         "The public lab is a place to read security research. You may browse normally, examine published source, and reproduce documented work on infrastructure you own or have permission to use. A public link, a published method, or an admission decision grants no authority to test someone else's system."),
        ("Permission for live testing",
         f"Active testing of the lab or related services requires written permission from the relevant owner before testing begins. A request should identify the intended system, purpose, proposed activity, and time window. Only the expressly approved scope is authorized. Contact {CONTACT}.",
         "Attempts to defeat access controls, disrupt service, collect other visitors’ information, or obtain nonpublic data are prohibited. Cloudflare, GitHub, and other independently operated services set their own testing rules."),
        ("If you encounter a problem",
         "Stop once you have enough information to report what you observed during ordinary use. If information belonging to someone else appears, avoid opening further records, retaining copies, or sharing it. A private description of the circumstances is enough for an initial report."),
        ("Private reporting channel",
         f"Send the affected public URL, approximate time and time zone, what you expected, and what you observed. Omit credentials, cookie values, personal information, and unredacted logs. Use email rather than public issues for a security report. Send reports to {CONTACT}.",
         "The operator may follow up privately for clarification. Coordinate publication of sensitive details while the operator investigates. Reporting an issue does not grant permission for additional testing or create an entitlement to payment."),
        ("Service protection",
         'The operator may limit or revoke access and investigate records reasonably related to suspected abuse. The <a href="/privacy">Privacy Policy</a> describes the information available for that purpose. For an error in research data or interpretation, use the correction process in <a href="/ai-disclosure">AI Disclosure &amp; Research Integrity</a>.'),
    )),
    "/ai-disclosure": ("AI Disclosure & Research Integrity", "How AI assistance, measured results, and planned research are identified.", (
        ("AI assistance in producing the site",
         "AI coding and writing tools assisted with the lab's implementation and editorial drafting. Nicolas Gioanni is responsible for the material published here and for decisions about corrections. AI-generated text can introduce errors in code, descriptions, and citations. The published method and run records are the basis for evaluating a measured claim."),
        ("Visitor information and models",
         "The current public site has no visitor-facing model or prompt submission. It sends no visitor prompts or telemetry to a model provider. Cloudflare processes browser signals for security as described in the privacy notice. Research about agents or retrieval systems does not turn a visit into a model evaluation. " +
         '<a href="/privacy">Privacy Policy</a>'),
        ("How to read a published measurement",
         "A measured result identifies the test inputs, tool and version, expected observations, actual outputs, and linked records. Compare the count in each named test case with its expectation. A count of matching observations describes that experiment and cannot establish a general detection rate.",
         "The lab uses synthetic test material for the published baseline. Outputs from tools are experimental observations. Written interpretations explain their significance. When publishing a model-assisted experiment, the lab will identify the model and its role, the task and data used, and how its output was evaluated."),
        ("Planned work and corrections",
         "A track labeled Planned describes a research question. It carries no measured result until a study and its evidence have been published.",
         f"If a claim and its supporting record differ, send the study title, the record or version you consulted, the disputed claim, and your reasoning to {CONTACT}. When the lab makes a material correction, it will identify the affected finding and explain what changed so readers can distinguish it from the original publication."),
    )),
}

POLICY_TITLES = {path: title for path, (title, _, _) in POLICIES.items()}


def build_policies():
    """Return one main-inner fragment per public policy, using the portfolio legal layout."""
    pages = {}
    for path, (title, description, sections) in POLICIES.items():
        if path == "/access-notice":
            body = notice_html(dialog=False)
        else:
            blocks = []
            for heading, *paragraphs in sections:
                copy = "".join(f"<p>{paragraph}</p>" for paragraph in paragraphs)
                blocks.append(f"<section><h2>{escape(heading)}</h2>{copy}</section>")
            body = "\n".join(blocks)
        pages[path] = f'''<div class="page-container page-container--legal">
  <div class="motion-reveal motion-reveal--delay-none page-intro page-intro--panel">
    <div class="glass-surface glass-surface--strong page-intro__surface"><header class="section-header section-header--page">
      <div class="section-header__copy"><p class="eyebrow">Site notice</p><h1 class="page-title" tabindex="-1">{escape(title)}</h1><p class="page-description">{escape(description)}</p></div>
    </header></div>
  </div>
  <article class="glass-surface glass-surface--strong legal-document">
    <header class="legal-document__meta"><h2 class="visually-hidden">Notice details</h2><p class="legal-document__effective-date"><span>Effective date:</span> <time datetime="{EFFECTIVE_DATE}">{DATE_LABEL}</time></p></header>
    <div class="legal-document__body">{body}</div>
  </article>
</div>'''
    return pages


# Change automatically whenever the policies that accompany an agreement change.
POLICY_REVISION = sha256(json.dumps(build_policies(), sort_keys=True).encode()).hexdigest()[:16]
