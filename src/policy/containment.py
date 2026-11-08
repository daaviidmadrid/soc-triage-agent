"""Level 4: turns the LLM's free-text suggestions into containment actions a person can approve. Plain code.

The LLM only writes suggestions in a ticket. This module decides, from section 4 of politica_soc.md,
data/02_inventario/servicios_negocio.csv and the CMDB:
- which of the mock's 7 actions a suggestion means, if any. Anything else stays a suggestion for a person;
- the exact target: a CMDB hostname, a directory account, an indicator, a message or an access key.
  Text the LLM wrote is only a hint, and a target must exist where it is looked up;
- who must approve: N2, N2 plus the service owner for a server, N2 plus the business for tills and web
  front ends. A person approves every action, including block_ioc and purge_email (docs/decisions.md);
- what refuses outright: anything on the OT network, our own infrastructure, IPs shared by many people.
Nothing here calls the mock API's /approvals or /containment. Only src/app/main.py does, after people approve.
"""

import csv
import hashlib
import ipaddress
import re
import unicodedata
from functools import lru_cache
from pathlib import Path

from contracts.models import ActionProposal, Approval
from src.tools.context import SHARED_IPS

SERVICES_FILE = Path(__file__).resolve().parents[2] / "data" / "02_inventario" / "servicios_negocio.csv"

OT_ZONES = {"LOGISTICS-OT"}
OWN_DOMAINS = ("tarvia.example",)
INTERNAL_NETWORKS = [
    ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
]
# Section 4 of the policy: don't block legitimate dual-use services across the company without N2.
DUAL_USE = ("mega.nz", "mega.io", "anydesk.com", "anydesk.net", "teamviewer.com", "wetransfer.com", "dropbox.com")
WORKSTATION_TYPES = {"Portátil"}
TILL_TYPES = {"TPV"}
WEB_FRONT_TYPES = {"Frontal web"}

ANALYST, N2 = "Analista SOC", "N2"

ACTION_NAMES = {
    "isolate_host": "Aislar el equipo",
    "disable_user": "Deshabilitar la cuenta",
    "revoke_sessions": "Revocar las sesiones",
    "reset_password": "Forzar cambio de contraseña",
    "block_ioc": "Bloquear el indicador",
    "purge_email": "Purgar el correo de todos los buzones",
    "disable_access_key": "Desactivar la clave cloud",
}
IMPACT = {
    "disable_user": "La persona no podrá trabajar con esta cuenta hasta que se reactive.",
    "revoke_sessions": "La persona tendrá que volver a iniciar sesión en todas sus aplicaciones.",
    "reset_password": "La persona necesitará una contraseña nueva para volver a entrar.",
    "block_ioc": "Nadie en Tarvia podrá conectar con este indicador desde el proxy, el correo ni el EDR.",
    "purge_email": "El correo desaparece de todos los buzones que lo recibieron.",
    "disable_access_key": "Todo lo que use esta clave dejará de funcionar.",
}

PATTERNS = {
    "disable_access_key": re.compile(
        r"(clave|claves|credencial\w*)\s+(de\s+acceso|cloud|aws|iam)|access\s*keys?|\bakia[0-9a-z]{16}"
    ),
    "purge_email": re.compile(
        r"\bpurg\w*|\b(elimin|borr|retir)\w*\s+(el|los|este|ese|dicho)?\s*(correo|mensaje|email)s?\b(?!\s+de\s+la\s+regla)"
    ),
    "isolate_host": re.compile(r"\baisl\w*|\bisolat\w*|\bcuarentena\b"),
    "revoke_sessions": re.compile(
        r"\brevoc\w*(\s+\w+){0,4}\s+sesion|\b(cerrar|invalidar|terminar|revocar)\w*(\s+\w+){0,4}\s+(sesion|sesiones|token|tokens)\b|\brevoke\b|\bsign.?out\b"
    ),
    "reset_password": re.compile(r"(contrasen|password|passwd)"),
    "disable_user": re.compile(
        r"\b(deshabilit|desactiv|bloque|suspend|disabl)\w*\s+(\w+\s+){0,2}(cuenta|usuario|account|user)\b"
    ),
    "block_ioc": re.compile(r"\bbloque\w*|\bblock\w*"),
}
PASSWORD_VERB = re.compile(r"\b(forz|cambi|restablec|reset|rot|regener|renov|resete)\w*")
REGLA = re.compile(r"\bregla\b|\brule\b")

UPN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_USER = re.compile(r"\b[A-Za-z][A-Za-z0-9-]*\\([A-Za-z0-9._-]+)")
USERNAME = re.compile(r"\b(?:svc_[a-z0-9_]+|adm\.[a-z0-9._-]+|ext\.[a-z0-9._-]+|[a-z]+\.[a-z]+[0-9]?)\b")
IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
SHA256 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
TOKEN = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*\d[A-Z0-9-]*\b")
ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")


def _plain(text):
    text = unicodedata.normalize("NFKD", str(text or "")).encode("ascii", "ignore").decode()
    return text.lower()


def _internal(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in INTERNAL_NETWORKS)


def _own_domain(domain):
    return any(domain == own or domain.endswith("." + own) for own in OWN_DOMAINS)


def actions_in(text):
    """Which of the 7 actions a suggestion asks for. One suggestion can hold two, as the policy's own row does."""
    plain = _plain(text)
    found = []
    for action, pattern in PATTERNS.items():
        if not pattern.search(plain):
            continue
        if action == "reset_password" and not PASSWORD_VERB.search(plain):
            continue
        if action == "purge_email" and REGLA.search(plain):
            continue  # removing a mailbox rule isn't purging an email
        if action == "block_ioc" and "disable_user" in found and not (IP.search(text) or SHA256.search(text)):
            continue  # "bloquear la cuenta" disables an account
        found.append(action)
    return found


# --- the business side -----------------------------------------------------------------------


def _expand(pattern):
    """'WEB-ECOM01..04' -> WEB-ECOM01 ... WEB-ECOM04. 'POS-T*' stays a prefix."""
    found = re.fullmatch(r"(.*?)(\d+)\.\.(\d+)", pattern)
    if not found:
        return [pattern]
    prefix, first, last = found.group(1), found.group(2), found.group(3)
    return [f"{prefix}{n:0{len(first)}d}" for n in range(int(first), int(last) + 1)]


@lru_cache(maxsize=1)
def services():
    try:
        with open(SERVICES_FILE, encoding="utf-8", newline="") as file:
            return tuple(csv.DictReader(file))
    except OSError:
        return ()


def service_of(asset):
    """The business service row for a CMDB asset: by its listed hostname, else by the service's name."""
    hostname = str(asset.get("hostname") or "")
    for row in services():
        for item in str(row.get("activos") or "").split(","):
            for pattern in _expand(item.strip()):
                if pattern == hostname or (pattern.endswith("*") and hostname.startswith(pattern[:-1])):
                    return row
    name = str(asset.get("business_service") or "")
    return next(
        (row for row in services() if name and (name.startswith(row["servicio"]) or row["servicio"].startswith(name))),
        None,
    )


def isolation_approvers(asset):
    """Section 4 of the policy. Returns (roles, business impact, warnings)."""
    service = service_of(asset)
    owner = (service or {}).get("responsable") or "responsable no registrado"
    impact = f"{(service or {}).get('servicio') or asset.get('business_service') or 'Servicio sin registrar'}: {(service or {}).get('impacto') or 'impacto no registrado'}."
    kind = asset.get("type")
    if kind in WORKSTATION_TYPES:
        return [N2], "La persona se queda sin su equipo hasta que se restaure.", []
    warnings = (
        []
        if service
        else ["El servicio de este equipo no figura en servicios_negocio.csv: confirma quién es el responsable."]
    )
    if kind in TILL_TYPES or kind in WEB_FRONT_TYPES:
        return [N2, f"Negocio ({owner})"], f"Impacto en ventas. {impact}", warnings
    return [N2, f"Responsable del servicio ({owner})"], impact, warnings


# --- targets ---------------------------------------------------------------------------------


def _accounts(text, ticket, lookup_user):
    """Directory accounts named in the text. A display name is never enough."""
    keys = list(dict.fromkeys([*UPN.findall(text), *DOMAIN_USER.findall(text), *USERNAME.findall(text)]))
    found = []
    for key in keys:
        user = lookup_user(key)
        if user and user.get("upn") and user["upn"] not in [u["upn"] for u in found]:
            found.append(user)
    if found:
        return found, []
    affected = [u for u in ((ticket.get("affected") or {}).get("users") or []) if isinstance(u, str)]
    users = [lookup_user(u) for u in affected]
    users = [u for u in users if u and u.get("upn")]
    if len(users) == 1:
        return users, ["La sugerencia no nombra la cuenta exacta: se usa la única cuenta afectada del ticket."]
    return [], []


def _hosts(text, lookup_asset):
    found = []
    for key in [*TOKEN.findall(text), *[ip for ip in IP.findall(text) if _internal(ip)]]:
        asset = lookup_asset(key)
        if asset and asset.get("hostname") and asset["hostname"] not in [a["hostname"] for a in found]:
            found.append(asset)
    return found


def _known_values(alert, ticket):
    """Indicators the alert or the ticket's checked enrichment already hold, so a domain can't come from thin air."""
    values = set()
    entities = alert.get("entities") if isinstance(alert.get("entities"), dict) else {}
    for key in ("domains", "urls", "ips"):
        for item in entities.get(key) or []:
            values.add(str(item).lower())
    for item in ticket.get("enrichment") or []:
        if isinstance(item, dict) and item.get("indicator"):
            values.add(str(item["indicator"]).lower())
    return values


def _indicators(text, alert, ticket):
    """Exact indicators: IPs and hashes by their format, domains only if the alert or ticket already holds them."""
    known = _known_values(alert, ticket)
    found = [*IP.findall(text), *[h.lower() for h in SHA256.findall(text)]]
    for value in known:
        domain = value.split("://", 1)[-1].split("/", 1)[0]
        if "." in domain and not IP.fullmatch(domain) and domain in text.lower():
            found.append(domain)
    return list(dict.fromkeys(found)), known


# --- building proposals ----------------------------------------------------------------------


def proposal_id(run_id, action, target):
    return "ACT-" + hashlib.sha256(f"{run_id}|{action}|{target}".encode()).hexdigest()[:12].upper()


def propose(ticket, alert, lookup_asset, lookup_user, run_id=""):
    """Returns (proposals, not_proposed). not_proposed explains every suggestion that didn't become an action."""
    alert = alert if isinstance(alert, dict) else {}
    evidence = alert.get("evidence") if isinstance(alert.get("evidence"), dict) else {}
    proposals, not_proposed = {}, []

    def add(action, target, suggestion, impact, approvers, warnings=(), justification=""):
        pid = proposal_id(run_id, action, target)
        if pid not in proposals:
            proposals[pid] = ActionProposal(
                proposal_id=pid,
                ticket_id=str(ticket.get("ticket_id") or ""),
                run_id=run_id,
                action=action,
                target=target,
                suggestion=suggestion[:300],
                justification=justification[:500],
                business_impact=impact,
                approvers=approvers,
                warnings=list(dict.fromkeys(warnings)),
            )

    def refuse(suggestion, reason):
        not_proposed.append({"suggestion": suggestion[:300], "reason": reason})

    for item in ticket.get("recommended_actions") or []:
        if not isinstance(item, dict) or not item.get("requires_approval"):
            continue  # close or escalate is the ticket's own decision, not containment
        suggestion = f"{item.get('action') or ''} → {item.get('target') or ''}".strip(" →")
        text = f"{item.get('action') or ''} {item.get('target') or ''}"
        justification = str(item.get("justification") or "")
        actions = actions_in(item.get("action") or "")
        if not actions:
            refuse(
                suggestion, "No es una de las 7 acciones de la API simulada: queda como sugerencia para una persona."
            )
            continue
        for action in actions:
            if action in ("revoke_sessions", "reset_password", "disable_user"):
                users, warnings = _accounts(text, ticket, lookup_user)
                if not users:
                    refuse(suggestion, "No nombra una cuenta que exista en el directorio.")
                for user in users:
                    extra = list(warnings)
                    if action == "disable_user" and user.get("account_type") == "service":
                        extra.append("Es una cuenta de servicio: deshabilitarla puede parar un proceso de negocio.")
                    add(action, user["upn"], suggestion, IMPACT[action], [N2], extra, justification)
            elif action == "isolate_host":
                assets = _hosts(text, lookup_asset)
                if not assets:
                    refuse(suggestion, "No nombra un equipo que exista en la CMDB.")
                for asset in assets:
                    if asset.get("zone") in OT_ZONES:
                        refuse(
                            suggestion,
                            f"{asset['hostname']} está en la red OT: el SOC nunca actúa ahí, solo escala a Operaciones.",
                        )
                        continue
                    approvers, impact, warnings = isolation_approvers(asset)
                    add(action, asset["hostname"], suggestion, impact, approvers, warnings, justification)
            elif action == "block_ioc":
                indicators, known = _indicators(text, alert, ticket)
                if not indicators:
                    refuse(suggestion, "No nombra un indicador exacto (IP, hash completo o dominio de la alerta).")
                for value in indicators:
                    if IP.fullmatch(value) and (_internal(value) or value in SHARED_IPS):
                        refuse(
                            suggestion, f"{value} es una IP interna o compartida por muchas personas: no se bloquea."
                        )
                        continue
                    if _own_domain(value):
                        refuse(suggestion, f"{value} es un dominio propio: no se bloquea.")
                        continue
                    warnings, approvers = [], [ANALYST]
                    if any(value == d or value.endswith("." + d) for d in DUAL_USE) or "anydesk" in value:
                        warnings.append(
                            "Servicio legítimo de uso dual: bloquearlo para toda la empresa necesita N2 (política, apartado 4)."
                        )
                        approvers = [N2]
                    if value.lower() not in known and not SHA256.fullmatch(value):
                        warnings.append("Este indicador no aparece en la alerta: compruébalo antes de bloquearlo.")
                    add(action, value, suggestion, IMPACT[action], approvers, warnings, justification)
            elif action == "purge_email":
                message_id = evidence.get("message_id")
                if not isinstance(message_id, str) or not message_id:
                    refuse(
                        suggestion, "La alerta no trae el identificador del mensaje: no se puede purgar con exactitud."
                    )
                    continue
                add(action, message_id, suggestion, IMPACT[action], [ANALYST], [], justification)
            elif action == "disable_access_key":
                keys = ACCESS_KEY.findall(text)
                for cloud in (alert.get("entities") or {}).get("cloud") or []:
                    if isinstance(cloud, dict) and cloud.get("access_key"):
                        keys.append(str(cloud["access_key"]))
                if not keys:
                    refuse(suggestion, "No hay una clave de acceso exacta en la alerta.")
                for key in dict.fromkeys(keys):
                    add(action, key, suggestion, IMPACT[action], [N2], [], justification)
    return list(proposals.values()), not_proposed


# --- people's approvals ----------------------------------------------------------------------


class ApprovalProblem(ValueError):
    """The approval or execution can't go ahead. The message is safe to show."""


def approve(proposal, role, approver, at):
    """Adds one person's approval for one role. Every role needs a different person."""
    approver = " ".join(str(approver or "").split())
    if proposal.status not in ("proposed", "approved"):
        raise ApprovalProblem("Esta acción ya no admite aprobaciones.")
    if role not in proposal.approvers:
        raise ApprovalProblem("Ese papel no tiene que aprobar esta acción.")
    if len(approver) < 2:
        raise ApprovalProblem("Indica el nombre de la persona que aprueba.")
    if any(a.role == role for a in proposal.approvals):
        raise ApprovalProblem("Ese papel ya ha aprobado esta acción.")
    if any(a.approver.lower() == approver.lower() for a in proposal.approvals):
        raise ApprovalProblem("Cada papel lo tiene que aprobar una persona distinta.")
    proposal.approvals.append(Approval(role=role, approver=approver, at=at))
    if {a.role for a in proposal.approvals} == set(proposal.approvers):
        proposal.status = "approved"
    return proposal


def missing_roles(proposal):
    return [role for role in proposal.approvers if role not in {a.role for a in proposal.approvals}]


def ready_to_run(proposal):
    """Raises ApprovalProblem unless every role has approved and the action hasn't run."""
    if proposal.status == "executed":
        raise ApprovalProblem("Esta acción ya se ejecutó: cada aprobación sirve una sola vez.")
    if proposal.status in ("refused", "rejected"):
        raise ApprovalProblem("Esta acción fue rechazada y no se puede ejecutar.")
    missing = missing_roles(proposal)
    if missing:
        raise ApprovalProblem("Faltan aprobaciones de: " + ", ".join(missing) + ".")


def approver_record(proposal):
    """What the mock's /approvals receives: every role with the person who approved it."""
    return "; ".join(f"{a.role}: {a.approver}" for a in proposal.approvals)


# --- structured steps (level 3 reports) --------------------------------------------------------

MESSAGE_ID = re.compile(r"^<[^<>\s]+@[^<>\s]+>$")
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


class StepRefused(ValueError):
    """A step can't become an action. The message is safe to show."""


def check_step(action, target, lookup_asset, lookup_user):
    """One explicit (action, target), as an incident report proposes it. Applies the same rules as propose():
    the target must exist where it is looked up, OT, internal or shared IPs and our own domains are refused,
    and approvers come from section 4 of the policy. Returns {"target", "approvers", "business_impact", "warnings"}
    with the canonical target, or raises StepRefused."""
    action, target = str(action or "").strip(), str(target or "").strip()
    if action not in ACTION_NAMES:
        raise StepRefused("No es una de las 7 acciones de la API simulada.")
    if not target:
        raise StepRefused("No tiene objetivo.")
    if action in ("revoke_sessions", "reset_password", "disable_user"):
        user = lookup_user(target)
        if not user or not user.get("upn"):
            raise StepRefused("No nombra una cuenta que exista en el directorio.")
        warnings = []
        if action == "disable_user" and (
            user.get("account_type") == "service" or str(user["upn"]).startswith(("svc_", "svc."))
        ):
            warnings.append("Es una cuenta de servicio: deshabilitarla puede parar un proceso de negocio.")
        return {"target": user["upn"], "approvers": [N2], "business_impact": IMPACT[action], "warnings": warnings}
    if action == "isolate_host":
        asset = lookup_asset(target)
        if not asset or not asset.get("hostname"):
            raise StepRefused("No nombra un equipo que exista en la CMDB.")
        if asset.get("zone") in OT_ZONES:
            raise StepRefused(
                f"{asset['hostname']} está en la red OT: el SOC nunca actúa ahí, solo escala a Operaciones."
            )
        approvers, impact, warnings = isolation_approvers(asset)
        return {"target": asset["hostname"], "approvers": approvers, "business_impact": impact, "warnings": warnings}
    if action == "block_ioc":
        value = target.lower()
        if "://" in value:
            value = value.split("://", 1)[1].split("/", 1)[0]
        if IP.fullmatch(value):
            if _internal(value) or value in SHARED_IPS:
                raise StepRefused(f"{value} es una IP interna o compartida por muchas personas: no se bloquea.")
        elif not (SHA256.fullmatch(value) or DOMAIN.fullmatch(value)):
            raise StepRefused("Solo se bloquean IPs, dominios o hashes completos.")
        elif _own_domain(value):
            raise StepRefused(f"{value} es un dominio propio: no se bloquea.")
        if any(value == d or value.endswith("." + d) for d in DUAL_USE) or "anydesk" in value:
            return {
                "target": value,
                "approvers": [N2],
                "business_impact": IMPACT[action],
                "warnings": [
                    "Servicio legítimo de uso dual: bloquearlo para toda la empresa necesita N2 (política, apartado 4)."
                ],
            }
        return {"target": value, "approvers": [ANALYST], "business_impact": IMPACT[action], "warnings": []}
    if action == "purge_email":
        if not MESSAGE_ID.fullmatch(target):
            raise StepRefused("No es un identificador de mensaje exacto (<...@...>).")
        return {"target": target, "approvers": [ANALYST], "business_impact": IMPACT[action], "warnings": []}
    if not ACCESS_KEY.fullmatch(target):
        raise StepRefused("No es una clave de acceso exacta.")
    return {"target": target, "approvers": [N2], "business_impact": IMPACT[action], "warnings": []}


def proposals_from_steps(steps, key, run_id, lookup_asset, lookup_user):
    """ActionProposals for a report's containment steps, checked again with check_step. key is the incident or
    ticket the report covers; it goes in ticket_id, so the containment log ties actions to that report.
    Returns (proposals, not_proposed)."""
    proposals, not_proposed = {}, []
    for step in steps or []:
        step = step if isinstance(step, dict) else {}
        suggestion = f"{step.get('action') or ''} → {step.get('target') or ''}".strip(" →")
        try:
            checked = check_step(step.get("action"), step.get("target"), lookup_asset, lookup_user)
        except StepRefused as refusal:
            not_proposed.append({"suggestion": suggestion[:300], "reason": str(refusal)})
            continue
        pid = proposal_id(run_id, step["action"], checked["target"])
        if pid in proposals:
            continue
        written = str(step.get("business_impact") or "").strip()
        # The report's text already starts with the same rule's impact when investigate checked it; don't say it twice.
        impact = (
            written
            if written.startswith(checked["business_impact"])
            else " ".join(p for p in (checked["business_impact"], written) if p)
        )
        proposals[pid] = ActionProposal(
            proposal_id=pid,
            ticket_id=key,
            run_id=run_id,
            action=step["action"],
            target=checked["target"],
            suggestion=suggestion[:300],
            justification=str(step.get("justification") or "")[:500],
            business_impact=impact[:1000],
            approvers=checked["approvers"],
            warnings=checked["warnings"],
        )
    return list(proposals.values()), not_proposed


def step_checker(lookup_asset, lookup_user):
    """check_step bound to CMDB and directory lookups, for src/agent/investigate.py, which never imports this module.
    A lookup the mock can't answer counts as not found."""

    def safe(fetch):
        def lookup(key):
            key = str(key or "").strip()
            if not key or "/" in key or len(key) > 200:
                return None
            try:
                return fetch(key)
            except Exception:
                return None

        return lookup

    asset, user = safe(lookup_asset), safe(lookup_user)
    return lambda action, target: check_step(action, target, asset, user)
