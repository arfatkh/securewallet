"""W13 inactivity timeout: enforced by the server, not only by the browser."""
import time

from .test_security import client, flag, fresh_data, login  # noqa: F401  (fresh_data: autouse reset)


def set_idle(c, seconds: int) -> None:
    assert c.put("/api/lab/settings/session_idle_seconds", json={"value": str(seconds)}).status_code == 200


def test_W13_idle_session_is_ended_by_the_server():
    admin, _ = login("ali")
    set_idle(admin, 15)
    sara, _ = login("sara")
    assert sara.get("/api/me").status_code == 200
    time.sleep(17)
    r = sara.get("/api/me")
    assert r.status_code == 401 and r.json()["code"] == "session_idle"
    assert sara.get("/api/me").status_code == 401                    # stays ended
    assert sara.post("/api/auth/refresh").status_code == 401         # and can't be revived by refreshing


def test_W13_activity_keeps_the_session_alive():
    admin, _ = login("ali")
    set_idle(admin, 15)
    sara, _ = login("sara")
    for _ in range(3):                                               # 27 s in total, never 15 s idle
        time.sleep(9)
        assert sara.post("/api/auth/heartbeat").status_code == 200
    assert sara.get("/api/me").status_code == 200


def test_W13_without_the_control_an_idle_session_stays_usable():
    admin, _ = login("ali")
    set_idle(admin, 15)
    flag(admin, "session_timeout", False)
    sara, _ = login("sara")
    time.sleep(17)
    assert sara.get("/api/me").status_code == 200                    # before: unattended screen still works
    flag(admin, "session_timeout", True)
    time.sleep(17)                                                   # that request was activity: idle again
    r = sara.get("/api/me")
    assert r.status_code == 401 and r.json()["code"] == "session_idle"   # after


def test_W13_config_reports_the_limit():
    admin, _ = login("ali")
    set_idle(admin, 60)
    cfg = client().get("/api/config").json()["session"]
    assert cfg["idle_seconds"] == 60 and cfg["enforced"] is True
    assert admin.put("/api/lab/settings/session_idle_seconds", json={"value": "5"}).status_code == 422


def test_logout_ends_the_server_side_session():
    c, _ = login("bilal")
    assert c.post("/api/auth/logout", json={}).status_code == 200
    assert c.post("/api/auth/refresh").status_code == 401
