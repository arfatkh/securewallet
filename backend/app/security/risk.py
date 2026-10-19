"""W8: rule-based transfer risk scoring (Lecture 2 slides 32/37)."""
from dataclasses import asdict, dataclass, field

from ..config import settings


@dataclass
class Risk:
    level: str
    signals: list[str] = field(default_factory=list)

    @property
    def needs_step_up(self) -> bool:
        return self.level != "LOW"

    def as_dict(self) -> dict:
        return asdict(self)


def assess(amount: int, paid_before: bool) -> Risk:
    signals = []
    if amount > settings.stepup_amount:
        signals.append(f"amount above Rs {settings.stepup_amount // 100:,}")
    if not paid_before and amount > settings.new_payee_amount:
        signals.append(f"first payment to this person above Rs {settings.new_payee_amount // 100:,}")
    return Risk("MEDIUM" if signals else "LOW", signals)
