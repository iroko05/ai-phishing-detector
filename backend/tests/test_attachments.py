"""Тесты анализа вложений (offline)."""
from __future__ import annotations

from app.analyzers.attachments import scan_attachments
from app.schemas import AttachmentInfo


def test_no_attachments_skipped():
    report, rows = scan_attachments([])
    assert report.status == "skipped"
    assert rows == []


def test_dangerous_extension():
    report, rows = scan_attachments([AttachmentInfo(filename="invoice.exe",
                                                    size=1024,
                                                    content_type="application/x-msdownload")])
    assert rows[0]["risk"] >= 80
    ids = {e.rule_id for e in report.evidence}
    assert any(i.startswith("dangerous_ext") for i in ids)
    assert report.score >= 80


def test_double_extension_masking():
    report, rows = scan_attachments([AttachmentInfo(filename="договор.pdf.exe",
                                                    size=2048,
                                                    content_type="application/pdf")])
    ids = {e.rule_id for e in report.evidence}
    assert "double_extension" in ids
    assert rows[0]["risk"] >= 85


def test_macro_document():
    report, rows = scan_attachments([AttachmentInfo(filename="act.docm",
                                                    size=4096,
                                                    content_type="application/vnd.ms-word.document.macroEnabled.12")])
    ids = {e.rule_id for e in report.evidence}
    assert "macro_document" in ids
    assert rows[0]["risk"] >= 60


def test_executable_inside_archive():
    report, rows = scan_attachments([
        {"filename": "scan.zip", "size": 8192, "content_type": "application/zip",
         "members": ["readme.txt", "setup.exe"]},
    ])
    ids = {e.rule_id for e in report.evidence}
    assert "executable_in_archive" in ids


def test_password_protected_archive_hint_in_body():
    report, rows = scan_attachments([
        {"filename": "docs.zip", "size": 8192, "content_type": "application/zip",
         "members": []},
    ], body_text="Пароль: 12345")
    ids = {e.rule_id for e in report.evidence}
    assert "password_protected_archive" in ids


def test_lure_filename():
    report, rows = scan_attachments([AttachmentInfo(filename="Выписка_по_счёту.pdf",
                                                    size=1024,
                                                    content_type="application/pdf")])
    ids = {e.rule_id for e in report.evidence}
    assert "lure_filename" in ids
    # документ без явных угроз не должен сразу блокироваться
    assert report.score < 45


def test_clean_document_low_risk():
    report, rows = scan_attachments([AttachmentInfo(filename="photo.jpg",
                                                    size=500_000,
                                                    content_type="image/jpeg")])
    assert report.score < 20
    assert rows[0]["risk"] < 20


def test_many_attachments_aggravates():
    files = [AttachmentInfo(filename=f"file{i}.txt", size=10,
                            content_type="text/plain") for i in range(5)]
    report, rows = scan_attachments(files)
    ids = {e.rule_id for e in report.evidence}
    assert "many_attachments" in ids


def test_dangerous_mime_type():
    report, rows = scan_attachments([
        {"filename": "update.bin", "size": 1024,
         "content_type": "application/x-msdownload", "members": []},
    ])
    ids = {e.rule_id for e in report.evidence}
    assert "dangerous_mime" in ids
