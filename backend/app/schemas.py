import unicodedata

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator


class Strict(BaseModel):
    # Unknown fields are rejected, so a client can't smuggle in "balance" or "sender_id".
    model_config = ConfigDict(extra="forbid")


def normalise_username(v: str) -> str:
    return unicodedata.normalize("NFKC", v).strip().lower()


class RegisterIn(Strict):
    username: str = Field(min_length=3, max_length=24)
    full_name: str = Field(min_length=2, max_length=60)
    password: str = Field(min_length=1, max_length=128)
    device_key: dict | None = None

    @field_validator("username")
    @classmethod
    def _u(cls, v: str) -> str:
        v = normalise_username(v)
        if not v.replace("_", "").isalnum() or not v.isascii():
            raise ValueError("Use 3-24 letters, numbers or underscores.")
        return v

    @field_validator("full_name")
    @classmethod
    def _n(cls, v: str) -> str:
        v = " ".join(unicodedata.normalize("NFKC", v).split())
        if any(unicodedata.category(c).startswith("C") for c in v):
            raise ValueError("Name contains invalid characters.")
        return v


class LoginIn(Strict):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)
    # Public JWK of the browser's non-extractable P-256 key; binds the session to this device (W14).
    device_key: dict | None = None

    @field_validator("username")
    @classmethod
    def _u(cls, v: str) -> str:
        return normalise_username(v)


class TransferIn(Strict):
    to_username: str = Field(min_length=1, max_length=64)
    # StrictInt: 1.5, "100" and 1e3 are rejected outright. Money is whole paisa.
    amount: StrictInt
    note: str | None = Field(default=None, max_length=140)
    # W11: the 6-digit transaction PIN, required on every transfer.
    tpin: str | None = Field(default=None, pattern=r"^\d{6}$")

    @field_validator("to_username")
    @classmethod
    def _u(cls, v: str) -> str:
        return normalise_username(v)

    @field_validator("note")
    @classmethod
    def _note(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = "".join(c for c in v if not unicodedata.category(c).startswith("C")).strip()
        return v or None


class PasskeyVerifyIn(Strict):
    credential: dict
    nickname: str = Field(default="Passkey", min_length=1, max_length=40)


class AssertionIn(Strict):
    credential: dict


class LogoutIn(Strict):
    everywhere: bool = False


class BeneficiaryIn(Strict):
    username: str = Field(min_length=1, max_length=64)
    nickname: str | None = Field(default=None, max_length=40)
    # W11: adding a saved payee needs the transaction PIN, like a transfer.
    tpin: str | None = Field(default=None, pattern=r"^\d{6}$")

    @field_validator("username")
    @classmethod
    def _u(cls, v: str) -> str:
        return normalise_username(v)

    @field_validator("nickname")
    @classmethod
    def _nick(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = " ".join("".join(c for c in v if not unicodedata.category(c).startswith("C")).split())
        return v or None


class TpinSetIn(Strict):
    password: str = Field(min_length=1, max_length=128)       # re-authentication
    new_pin: str = Field(pattern=r"^\d{6}$")


class LabSettingIn(Strict):
    value: str = Field(min_length=1, max_length=64)


class FlagIn(Strict):
    enabled: bool
