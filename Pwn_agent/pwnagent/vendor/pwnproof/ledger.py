from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class EvidenceEntry:
    seq: int
    kind: str
    text: str
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )


class EvidenceLedger:
    """Persistent, compact memory that survives model context trimming."""

    ALLOWED_KINDS = {"fact", "hypothesis", "failure", "success", "artifact", "plan"}

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._entries: list[EvidenceEntry] = []
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    payload = json.loads(line)
                    self._entries.append(EvidenceEntry(**payload))
                except (ValueError, TypeError):
                    continue

    def add(self, kind: str, text: str) -> EvidenceEntry:
        normalized_kind = kind.strip().lower()
        if normalized_kind not in self.ALLOWED_KINDS:
            raise ValueError(f"unsupported ledger kind: {kind}")
        cleaned = " ".join(text.split()).strip()
        if not cleaned:
            raise ValueError("ledger text cannot be empty")
        cleaned = cleaned[:800]
        with self._lock:
            for entry in reversed(self._entries[-30:]):
                if entry.kind == normalized_kind and entry.text == cleaned:
                    return entry
            entry = EvidenceEntry(
                seq=(self._entries[-1].seq + 1) if self._entries else 1,
                kind=normalized_kind,
                text=cleaned,
            )
            self._entries.append(entry)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
            return entry

    def recent(self, limit: int = 24) -> list[EvidenceEntry]:
        with self._lock:
            return list(self._entries[-max(1, min(limit, 100)) :])

    def by_kind(self, kind: str, limit: int = 12) -> list[EvidenceEntry]:
        with self._lock:
            return [entry for entry in self._entries if entry.kind == kind][-limit:]

    def summary(self, limit: int = 24) -> str:
        entries = self.recent(limit)
        if not entries:
            return "Evidence ledger is empty."
        return "\n".join(f"{entry.seq:03d} [{entry.kind}] {entry.text}" for entry in entries)

    def as_dicts(self) -> list[dict]:
        with self._lock:
            return [asdict(entry) for entry in self._entries]

