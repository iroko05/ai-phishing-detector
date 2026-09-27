"""
Модуль 5. Проверка вложений.

Оценивает не только расширение, но и способ маскировки: двойные расширения,
RLO-переворот имени, исполняемый файл внутри архива, пароль от архива в теле
письма, «финансовые» названия-приманки и отсылки к известным эксплойтам.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from ..schemas import AttachmentInfo, Evidence, ModuleReport

DANGEROUS_EXT: Dict[str, int] = {
    ".exe": 90, ".scr": 88, ".com": 85, ".pif": 85, ".hta": 85, ".cpl": 80,
    ".msi": 75, ".msp": 75, ".lnk": 78, ".vbs": 85, ".vbe": 85, ".js": 82,
    ".jse": 85, ".wsf": 85, ".wsh": 85, ".ps1": 85, ".bat": 75, ".cmd": 75,
    ".chm": 70, ".jar": 68, ".iso": 62, ".img": 62, ".reg": 60, ".url": 45,
    ".application": 70, ".gadget": 75, ".searchconnector-ms": 60,
}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam"}
OFFICE_EXT = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
              ".pdf", ".pub", ".msg", ".one"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".ace", ".cab"}
HTML_LURE_EXT = {".html", ".htm", ".shtml", ".mhtml", ".xml", ".svg"}

INNER_EXEC_RE = re.compile(r"\.(exe|scr|vbs|js|hta|bat|cmd|ps1|lnk|jar)$", re.I)
LORE_NAME_RE = re.compile(
    r"(invoice|сч[её]т|счет|оплат|платеж|платёж|зарплат|salary|документ|договор|"
    r"scan|скан|выписка|накладн|акт|резюме|cv|order|заказ|посылк|delivery|"
    r"штраф|налог|долг|список|приказ)",
    re.I,
)
PASSWORD_HINT_RE = re.compile(r"(пароль|password|pwd)\s*[:\-]?\s*\S{2,}", re.I)
CVE_LURE_RE = re.compile(r"(follina|cve-\d{4}-\d+|externaldata|remote\s*template)", re.I)
RLO_CHAR = "\u202e"


def _ext(name: str) -> str:
    name = (name or "").lower().strip()
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1]


def _hidden_extension(name: str) -> str:
    """Возвращает пояснение, если тип файла спрятан (двойное расширение, RLO)."""
    if RLO_CHAR in (name or ""):
        return "право-ориентированный символ переворачивает имя файла"
    parts = (name or "").lower().split(".")
    if len(parts) < 3:
        return ""
    tail = "." + parts[-1]
    second = "." + parts[-2]
    if tail in DANGEROUS_EXT and second in (OFFICE_EXT | ARCHIVE_EXT | {".pdf", ".jpg", ".png"}):
        return f"двойное расширение: {second} маскирует {tail}"
    if second in DANGEROUS_EXT:
        return f"двойное расширение: реальный тип {second}"
    return ""


def _attachment_dicts(attachments: List[Any]) -> List[Dict[str, Any]]:
    """Принимает и AttachmentInfo, и сырые dict из парсера."""
    result: List[Dict[str, Any]] = []
    for item in attachments or []:
        if isinstance(item, AttachmentInfo):
            result.append({
                "filename": item.filename,
                "content_type": item.content_type,
                "size": item.size,
                "members": getattr(item, "members", []) or [],
            })
        elif isinstance(item, dict):
            result.append({
                "filename": str(item.get("filename") or "attachment.bin"),
                "content_type": str(item.get("content_type") or "").lower(),
                "size": int(item.get("size") or 0),
                "members": item.get("members") or [],
            })
    return result


def scan_attachments(attachments: List[Any], body_text: str = "") -> Tuple[ModuleReport, List[dict]]:
    """Возвращает (отчёт модуля, пофайловые вердикты для UI)."""
    items = _attachment_dicts(attachments)
    if not items:
        return (
            ModuleReport(score=0, status="skipped", comment="Вложений нет"),
            [],
        )

    evidence: List[Evidence] = []
    verdicts: List[dict] = []
    worst = 0

    for item in items:
        name = item["filename"]
        ext = _ext(name)
        ctype = item["content_type"]
        size = item["size"]
        reasons: List[str] = []
        risk = 0

        def raise_(rule_id: str, title: str, points: int, detail: str, floor: int) -> None:
            nonlocal risk, worst
            if points > risk:
                reasons.append(detail)
            risk = max(risk, floor)
            worst = max(worst, risk)
            if not any(e.rule_id == rule_id and e.detail == f"{name}: {detail}" for e in evidence):
                evidence.append(Evidence(
                    rule_id=rule_id, title=title, points=floor,
                    category="attachment", detail=f"{name}: {detail}",
                ))

        if ext in DANGEROUS_EXT:
            raise_(
                f"dangerous_ext{ext}", f"Опасное расширение {ext}",
                DANGEROUS_EXT[ext], f"ОС может выполнить файл напрямую ({ext})",
                DANGEROUS_EXT[ext],
            )
        if ext in MACRO_EXT:
            raise_("macro_document", "Документ Office с макросами", 60,
                   "макросы — типичный вектор доставки малвари", 60)

        hidden = _hidden_extension(name)
        if hidden:
            raise_("double_extension", "Маскировка реального типа файла", 85, hidden, 85)

        if ext in HTML_LURE_EXT:
            raise_("html_attachment", "HTML-вложение вместо документа", 45,
                   "HTML-файл часто используется как «страница входа» банка", 45)

        members = item.get("members") or []
        inner_exec = [str(m) for m in members if INNER_EXEC_RE.search(str(m))]
        if inner_exec:
            raise_("executable_in_archive", "Исполняемый файл внутри архива", 70,
                   f"в архиве лежат {', '.join(inner_exec[:3])}", 70)
        elif ext in ARCHIVE_EXT and PASSWORD_HINT_RE.search(body_text or ""):
            raise_("password_protected_archive",
                   "Пароль от архива передан в теле письма", 55,
                   "зашифрованный архив не разбирается антивирусом шлюза", 55)
        elif ext in ARCHIVE_EXT:
            raise_("archive_attachment", "Архив во вложении", 25,
                   "архивы применяются для обхода фильтра содержимого", 25)

        if LORE_NAME_RE.search(name):
            raise_("lure_filename", "Название-приманка", 25,
                   "типичная приманка («счёт», «накладная», «выписка»)", 25)

        if CVE_LURE_RE.search(name) or CVE_LURE_RE.search(body_text or ""):
            raise_("exploit_lure", "Отсылка к известному эксплойту", 65,
                   "в имени/тексте упоминается CVE или техника эксплуатации", 65)

        dangerous_mimes = {
            "application/x-msdownload", "application/x-msdos-program",
            "application/x-executable", "application/x-sh", "application/x-sharedlib",
            "application/vnd.microsoft.portable-executable",
        }
        if ctype in dangerous_mimes:
            raise_("dangerous_mime", "Опасный MIME-тип", 80,
                   f"MIME {ctype} не встречается в деловой переписке", 80)

        verdicts.append({
            "filename": name,
            "extension": ext,
            "content_type": ctype,
            "size": size,
            "risk": risk,
            "reasons": reasons,
        })

    if worst == 0:
        evidence.append(Evidence(
            rule_id="attachments_present", title="Вложения присутствуют", points=5,
            category="attachment",
            detail=f"{len(items)} файл(ов): {', '.join(v['filename'] for v in verdicts[:5])} — "
                   "явных угроз не найдено",
        ))
        worst = 5

    if len(items) >= 4:
        worst = min(100, worst + 10)
        evidence.append(Evidence(
            rule_id="many_attachments", title="Много вложений в одном письме", points=10,
            category="attachment", detail=f"{len(items)} вложений",
        ))

    score = max(0, min(100, int(worst)))
    report = ModuleReport(
        score=score,
        status="suspicious" if score >= 45 else "ok",
        evidence=evidence,
        details={
            "count": len(items),
            "files": verdicts,
            "types": sorted({v["content_type"] for v in verdicts if v["content_type"]}),
        },
        comment=(f"Опасное вложение: {verdicts[0]['filename']}"
                 if score >= 45 and verdicts else "Вложения проверены"),
    )
    return report, verdicts
