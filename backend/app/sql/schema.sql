-- SecureWallet schema. Applied once by the migration role (wallet_owner).
-- The API runs as wallet_app: a non-owner role without BYPASSRLS, so every
-- row-level-security policy below applies to it (control W1).

-- ---------------------------------------------------------------- identity
CREATE TABLE users (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username       text NOT NULL CHECK (username ~ '^[a-z0-9_]{3,24}$'),
    full_name      text NOT NULL CHECK (char_length(full_name) BETWEEN 2 AND 600),  -- AES-GCM ciphertext (W12)
    password_hash  text NOT NULL,
    role           text NOT NULL DEFAULT 'customer' CHECK (role IN ('customer', 'auditor', 'system')),
    failed_logins  integer NOT NULL DEFAULT 0,
    locked_until   timestamptz,
    tpin_hash          text,                 -- argon2id hash of the 6-digit transaction PIN (W11)
    tpin_set_at        timestamptz,
    tpin_failed        integer NOT NULL DEFAULT 0,
    tpin_locked_until  timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_username_key ON users (username);

-- The identity RLS policies compare against. Set per request with
-- set_config('app.user_id', <jwt sub>, true), i.e. SET LOCAL: scoped to one
-- DB transaction, so a pooled connection never carries a previous user's id.
CREATE FUNCTION app_uid() RETURNS uuid LANGUAGE sql STABLE AS
$$ SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$;

CREATE FUNCTION app_role() RETURNS text LANGUAGE sql STABLE AS
$$ SELECT COALESCE(NULLIF(current_setting('app.role', true), ''), 'anonymous') $$;

-- ---------------------------------------------------------------- money
CREATE TABLE wallets (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL UNIQUE REFERENCES users (id),
    balance     bigint NOT NULL DEFAULT 0,               -- paisa (1 Rs = 100 paisa), never float
    currency    char(3) NOT NULL DEFAULT 'PKR',
    status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'frozen')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT balance_non_negative CHECK (balance >= 0)
);

CREATE TABLE transactions (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ref          text NOT NULL UNIQUE,
    sender_id    uuid NOT NULL REFERENCES users (id),
    receiver_id  uuid NOT NULL REFERENCES users (id),
    amount       bigint NOT NULL,
    note         text CHECK (char_length(note) <= 800),   -- AES-GCM ciphertext (W12); 140 chars of any script fits
    status       text NOT NULL CHECK (status IN ('completed', 'failed')),
    reason       text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT amount_positive CHECK (amount > 0),
    CONSTRAINT no_self_transfer CHECK (sender_id <> receiver_id)
);
CREATE INDEX transactions_sender_idx ON transactions (sender_id, created_at DESC);
CREATE INDEX transactions_receiver_idx ON transactions (receiver_id, created_at DESC);

-- Total money in the system; conservation check used by the auditor's reconcile.
CREATE TABLE ledger_settings (
    id            boolean PRIMARY KEY DEFAULT true CHECK (id),
    total_supply  bigint NOT NULL
);

-- ---------------------------------------------------------------- request integrity
CREATE TABLE idempotency_keys (
    user_id       uuid NOT NULL REFERENCES users (id),
    key           text NOT NULL CHECK (char_length(key) BETWEEN 8 AND 80),
    request_hash  text NOT NULL,
    status_code   integer,
    response      jsonb,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, key)
);

CREATE TABLE pending_transfers (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES users (id),
    receiver_id  uuid NOT NULL REFERENCES users (id),
    amount       bigint NOT NULL CHECK (amount > 0),
    note         text CHECK (char_length(note) <= 800),
    nonce        bytea NOT NULL,
    challenge    bytea NOT NULL,
    risk         jsonb NOT NULL,
    status       text NOT NULL DEFAULT 'awaiting_passkey'
                 CHECK (status IN ('awaiting_passkey', 'completed', 'failed', 'expired', 'cancelled')),
    tx_id        uuid REFERENCES transactions (id),
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- sessions & passkeys
-- One row per signed-in session (= refresh-token family). Idle and absolute
-- timeouts (W13) and the device key binding (W14) live here.
CREATE TABLE sessions (
    id                   uuid PRIMARY KEY,
    user_id              uuid NOT NULL REFERENCES users (id),
    created_at           timestamptz NOT NULL DEFAULT now(),
    last_seen_at         timestamptz NOT NULL DEFAULT now(),
    absolute_expires_at  timestamptz NOT NULL,
    revoked_at           timestamptz,
    revoke_reason        text,
    device_jkt           text,           -- RFC 7638 thumbprint of the browser's non-extractable key
    ip                   text,
    user_agent           text
);

-- Single-use ids of device-key proofs (replay protection for W14).
CREATE TABLE dpop_jti (
    jti         text PRIMARY KEY,
    expires_at  timestamptz NOT NULL
);

CREATE TABLE refresh_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users (id),
    token_hash  text NOT NULL UNIQUE,          -- SHA-256 of the cookie value; raw token never stored
    family      uuid NOT NULL,
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE revoked_jti (
    jti         text PRIMARY KEY,
    expires_at  timestamptz NOT NULL
);

CREATE TABLE webauthn_credentials (
    id            bytea PRIMARY KEY,
    user_id       uuid NOT NULL REFERENCES users (id),
    public_key    bytea NOT NULL,                -- COSE public key; the private key never leaves the device
    sign_count    bigint NOT NULL DEFAULT 0,
    transports    text[],
    nickname      text NOT NULL,
    aaguid        text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);

CREATE TABLE webauthn_challenges (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users (id),
    challenge   bytea NOT NULL,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz
);

-- ---------------------------------------------------------------- accountability
CREATE TABLE audit_log (
    id           bigserial PRIMARY KEY,
    ts           timestamptz NOT NULL DEFAULT now(),
    request_id   text,
    actor_id     uuid,
    actor        text,
    role         text,
    action       text NOT NULL,
    outcome      text NOT NULL,
    status_code  integer,
    ip           text,
    detail       jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_log_ts_idx ON audit_log (ts DESC);

CREATE FUNCTION audit_log_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END $$;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

-- ---------------------------------------------------------------- demo lab
-- Demo-only tunables, e.g. a short idle timeout for the live demo.
CREATE TABLE lab_settings (
    name   text PRIMARY KEY,
    value  text NOT NULL
);

CREATE TABLE lab_flags (
    name         text PRIMARY KEY,
    enabled      boolean NOT NULL DEFAULT true,
    weakness     text NOT NULL,
    title        text NOT NULL,
    description  text NOT NULL
);

-- ---------------------------------------------------------------- the only way money moves
-- SECURITY DEFINER: runs as the table owner, so it may update the receiver's
-- wallet that RLS hides from the caller. It therefore takes the sender from
-- app_uid() instead of trusting a parameter, and re-validates everything.
CREATE FUNCTION transfer_funds(p_receiver uuid, p_amount bigint, p_note text)
RETURNS TABLE (tx_id uuid, tx_ref text, tx_status text, tx_reason text,
               sender_before bigint, sender_after bigint,
               receiver_before bigint, receiver_after bigint, locked boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_sender   uuid := app_uid();
    v_validate boolean;
    v_lock     boolean;
    s          wallets;
    r          wallets;
    v_ref      text := 'TX' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 10));
    v_id       uuid;
BEGIN
    IF v_sender IS NULL THEN
        RAISE EXCEPTION 'no authenticated user' USING ERRCODE = '28000';
    END IF;

    SELECT enabled INTO v_validate FROM lab_flags WHERE name = 'amount_validation';
    SELECT enabled INTO v_lock FROM lab_flags WHERE name = 'row_locking';
    v_validate := COALESCE(v_validate, true);
    v_lock := COALESCE(v_lock, true);

    IF v_validate THEN
        IF p_amount IS NULL OR p_amount <= 0 THEN
            RAISE EXCEPTION 'amount must be greater than zero' USING ERRCODE = '22023';
        END IF;
        IF p_amount > 50000000 THEN
            RAISE EXCEPTION 'amount exceeds the Rs 500,000 per-transfer limit' USING ERRCODE = '22023';
        END IF;
    END IF;
    IF p_receiver = v_sender THEN
        RAISE EXCEPTION 'cannot send money to yourself' USING ERRCODE = '22023';
    END IF;

    IF v_lock THEN
        -- Lock both rows in one fixed order (by user id) so A->B and B->A
        -- running together cannot deadlock, then read balances under the lock.
        PERFORM 1 FROM wallets WHERE user_id IN (v_sender, p_receiver) ORDER BY user_id FOR UPDATE;
        SELECT * INTO s FROM wallets WHERE user_id = v_sender;
        SELECT * INTO r FROM wallets WHERE user_id = p_receiver;
    ELSE
        -- LAB (row_locking off): read without locks and widen the race window.
        SELECT * INTO s FROM wallets WHERE user_id = v_sender;
        SELECT * INTO r FROM wallets WHERE user_id = p_receiver;
        PERFORM pg_sleep(0.3);
    END IF;

    IF s.id IS NULL OR r.id IS NULL THEN
        RAISE EXCEPTION 'wallet not found' USING ERRCODE = 'P0002';
    END IF;

    IF s.status <> 'active' OR r.status <> 'active' THEN
        INSERT INTO transactions (ref, sender_id, receiver_id, amount, note, status, reason)
        VALUES (v_ref, v_sender, p_receiver, p_amount, p_note, 'failed', 'wallet frozen')
        RETURNING id INTO v_id;
        RETURN QUERY SELECT v_id, v_ref, 'failed'::text, 'wallet frozen'::text,
                            s.balance, s.balance, r.balance, r.balance, v_lock;
        RETURN;
    END IF;

    IF s.balance < p_amount THEN
        INSERT INTO transactions (ref, sender_id, receiver_id, amount, note, status, reason)
        VALUES (v_ref, v_sender, p_receiver, p_amount, p_note, 'failed', 'insufficient funds')
        RETURNING id INTO v_id;
        RETURN QUERY SELECT v_id, v_ref, 'failed'::text, 'insufficient funds'::text,
                            s.balance, s.balance, r.balance, r.balance, v_lock;
        RETURN;
    END IF;

    -- Absolute writes from the values read above: correct under the lock,
    -- a classic lost update without it (which the lab demonstrates).
    UPDATE wallets SET balance = s.balance - p_amount WHERE id = s.id;
    UPDATE wallets SET balance = r.balance + p_amount WHERE id = r.id;

    INSERT INTO transactions (ref, sender_id, receiver_id, amount, note, status)
    VALUES (v_ref, v_sender, p_receiver, p_amount, p_note, 'completed')
    RETURNING id INTO v_id;

    RETURN QUERY SELECT v_id, v_ref, 'completed'::text, NULL::text,
                        s.balance, s.balance - p_amount, r.balance, r.balance + p_amount, v_lock;
END $$;

-- Auditor-only conservation check. Runs as owner so it sees every wallet,
-- but refuses anyone whose request context is not the auditor role.
CREATE FUNCTION reconcile_ledger()
RETURNS TABLE (username text, balance bigint, expected bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF app_role() <> 'auditor' THEN
        RAISE EXCEPTION 'auditor role required' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT u.username, w.balance,
           ((CASE WHEN u.role = 'system' THEN (SELECT total_supply FROM ledger_settings) ELSE 0 END)
            + COALESCE((SELECT sum(t.amount) FROM transactions t WHERE t.receiver_id = u.id AND t.status = 'completed'), 0)
            - COALESCE((SELECT sum(t.amount) FROM transactions t WHERE t.sender_id = u.id AND t.status = 'completed'), 0)
           )::bigint
    FROM users u JOIN wallets w ON w.user_id = u.id
    ORDER BY u.role DESC, u.username;
END $$;

-- ---------------------------------------------------------------- row-level security (W1)
-- ENABLE (not FORCE): policies bind every role except the table owner, so the
-- SECURITY DEFINER functions above keep working while wallet_app is restricted.
ALTER TABLE wallets ENABLE ROW LEVEL SECURITY;
CREATE POLICY wallets_read ON wallets FOR SELECT
    USING (user_id = app_uid() OR app_role() = 'auditor');
CREATE POLICY wallets_open ON wallets FOR INSERT
    WITH CHECK (user_id = app_uid() AND balance = 0);

ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
CREATE POLICY transactions_read ON transactions FOR SELECT
    USING (sender_id = app_uid() OR receiver_id = app_uid() OR app_role() = 'auditor');

ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY idempotency_own ON idempotency_keys
    USING (user_id = app_uid()) WITH CHECK (user_id = app_uid());

ALTER TABLE pending_transfers ENABLE ROW LEVEL SECURITY;
CREATE POLICY pending_own ON pending_transfers
    USING (user_id = app_uid()) WITH CHECK (user_id = app_uid());

ALTER TABLE webauthn_credentials ENABLE ROW LEVEL SECURITY;
CREATE POLICY passkeys_own ON webauthn_credentials
    USING (user_id = app_uid()) WITH CHECK (user_id = app_uid());

ALTER TABLE webauthn_challenges ENABLE ROW LEVEL SECURITY;
CREATE POLICY challenges_own ON webauthn_challenges
    USING (user_id = app_uid()) WITH CHECK (user_id = app_uid());

-- ---------------------------------------------------------------- least privilege for the API role
-- No UPDATE on wallets and no INSERT on transactions: balances change only
-- through transfer_funds().
GRANT SELECT, INSERT ON users TO wallet_app;
GRANT UPDATE (failed_logins, locked_until, tpin_hash, tpin_set_at, tpin_failed, tpin_locked_until) ON users TO wallet_app;
GRANT SELECT, INSERT, UPDATE ON sessions TO wallet_app;
GRANT SELECT, INSERT ON dpop_jti TO wallet_app;
GRANT SELECT ON lab_settings TO wallet_app;
GRANT SELECT, INSERT ON wallets TO wallet_app;
GRANT SELECT ON transactions TO wallet_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON idempotency_keys TO wallet_app;
GRANT SELECT, INSERT, UPDATE ON pending_transfers TO wallet_app;
GRANT SELECT, INSERT, UPDATE ON refresh_tokens TO wallet_app;
GRANT SELECT, INSERT ON revoked_jti TO wallet_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON webauthn_credentials TO wallet_app;
GRANT SELECT, INSERT, UPDATE ON webauthn_challenges TO wallet_app;
GRANT SELECT, INSERT ON audit_log TO wallet_app;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO wallet_app;
GRANT SELECT ON lab_flags TO wallet_app;
GRANT SELECT ON ledger_settings TO wallet_app;
REVOKE ALL ON FUNCTION transfer_funds(uuid, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION transfer_funds(uuid, bigint, text) TO wallet_app;
REVOKE ALL ON FUNCTION reconcile_ledger() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION reconcile_ledger() TO wallet_app;
