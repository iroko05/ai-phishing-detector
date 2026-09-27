"""
Минимальный приёмный SMTP-сервер для проверки писем «в потоке».

Реализован подмножеством RFC 5321 (HELO/EHLO, MAIL FROM, RCPT TO, DATA, QUIT,
RSET, NOOP) — этого достаточно, чтобы MTA (Postfix/Exim) мог отправлять письма
на проверку как на relay-хост, либо чтобы принимать почту напрямую.

Смысловая часть: после DATA вызывается ``handler({mail_from, rcpt_to, data})``,
который возвращает ``{"action": ..., "score": ..., "reason": ...}``.
Действия ``reject``/``block``/``quarantine`` → отвечаем 550 (MTA не доставляет
письмо дальше; отклонённая копия уже сохранена в карантине шлюза), остальное → 250.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger("gateway.mta.smtp")

MAX_LINE = 4096

# Действия, при которых письмо не должно уходить дальше по цепочке доставки
REJECT_ACTIONS = frozenset({"reject", "block", "quarantine"})


class SmtpFrontend:
    def __init__(self, host: str, port: int,
                 handler: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]],
                 *, max_message_mb: int = 25) -> None:
        self.host = host
        self.port = port
        self.handler = handler
        self.max_bytes = max_message_mb * 1024 * 1024
        self.accepted = 0
        self.rejected = 0
        self._server: Optional[asyncio.AbstractServer] = None

    async def serve(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.host,
                                                  self.port)
        # port=0 → ОС выделяет свободный порт (используется в тестах)
        if self._server.sockets:
            self.port = self._server.sockets[0].getsockname()[1]
        logger.info("SMTP-фронт слушает %s:%s", self.host, self.port)
        async with self._server:
            await self._server.serve_forever()

    def close(self) -> None:
        if self._server is not None:
            self._server.close()

    # ---------------------------------------------------------------- сессия
    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        mail_from = ""
        rcpt_to: List[str] = []
        too_big = False
        await self._send(writer, "220 antispam-gateway ESMTP ready")
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                if len(line) > MAX_LINE:
                    too_big = True
                    continue
                text = line.decode("utf-8", errors="replace").rstrip("\r\n")
                verb = text.split(" ", 1)[0].upper()

                if verb in ("HELO", "EHLO"):
                    await self._send(writer, "250-antispam-gateway")
                    await self._send(writer, "250 SIZE %d" % self.max_bytes)
                elif verb == "MAIL":
                    mail_from = self._extract_address(text)
                    rcpt_to = []
                    await self._send(writer, "250 OK")
                elif verb == "RCPT":
                    rcpt_to.append(self._extract_address(text))
                    await self._send(writer, "250 OK")
                elif verb == "DATA":
                    await self._send(writer, "354 send message data")
                    data = await self._read_data(reader)
                    if len(data) > self.max_bytes:
                        await self._send(writer, "552 message too large")
                        continue
                    action = await self._check(mail_from, rcpt_to, data, peer)
                    if action.get("action") in REJECT_ACTIONS:
                        await self._send(writer, "550 5.7.1 rejected: "
                                         + (action.get("reason") or "spam")[:180])
                    else:
                        await self._send(writer, "250 2.0.0 accepted "
                                         f"(score={action.get('score', 0)})")
                    mail_from, rcpt_to = "", []
                elif verb == "RSET":
                    mail_from, rcpt_to = "", []
                    await self._send(writer, "250 OK")
                elif verb == "NOOP":
                    await self._send(writer, "250 OK")
                elif verb == "QUIT":
                    await self._send(writer, "221 bye")
                    break
                else:
                    await self._send(writer, "502 command not implemented")
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception:  # noqa: BLE001
            logger.exception("smtp-сессия %s", peer)
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _read_data(self, reader: asyncio.StreamReader) -> str:
        chunks: List[str] = []
        total = 0
        while True:
            line = await reader.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace")
            if text in (".\r\n", ".\n"):
                break
            total += len(line)
            if total > self.max_bytes * 2:      # обрываем заведомо огромное письмо
                continue
            if text.startswith(".."):
                text = text[1:]
            chunks.append(text)
        return "".join(chunks)

    async def _check(self, mail_from: str, rcpt_to: List[str], data: str,
                     peer: Any) -> Dict[str, Any]:
        try:
            result = await self.handler({"mail_from": mail_from, "rcpt_to": rcpt_to,
                                         "data": data, "peer": peer})
        except Exception:  # noqa: BLE001
            logger.exception("проверка письма в SMTP-потоке")
            # Ошибка проверки не должна ломать почту: пропускаем, но пишем.
            return {"action": "deliver", "score": 0, "reason": "check failed"}
        if result.get("action") == "reject":
            self.rejected += 1
        else:
            self.accepted += 1
        return result

    @staticmethod
    async def _send(writer: asyncio.StreamWriter, text: str) -> None:
        writer.write((text + "\r\n").encode("utf-8"))
        await writer.drain()

    @staticmethod
    def _extract_address(line: str) -> str:
        start = line.find("<")
        end = line.find(">")
        if start != -1 and end > start:
            return line[start + 1:end]
        return line.split(":", 1)[-1].strip()
