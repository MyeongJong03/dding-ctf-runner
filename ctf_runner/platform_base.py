from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class PlatformAction:
    action: str
    live: bool
    network: bool
    status: str
    details: dict[str, Any]


def action_to_dict(action: PlatformAction) -> dict[str, Any]:
    return asdict(action)


class PlatformAdapter(Protocol):
    def discover_challenges(self, live: bool = False) -> PlatformAction:
        ...

    def get_challenge(self, challenge_id: str, live: bool = False) -> PlatformAction:
        ...

    def download_attachments(self, challenge_id: str, dest_dir: str | None = None, live: bool = False) -> PlatformAction:
        ...

    def start_instance(self, challenge_id: str, live: bool = False) -> PlatformAction:
        ...

    def submit_flag(self, challenge_id: str, flag: str, live: bool = False, confirm: bool = False) -> PlatformAction:
        ...
