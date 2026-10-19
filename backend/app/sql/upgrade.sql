-- Idempotent upgrades, run on every start after schema.sql. Safe on a database
-- created by an older version: existing data is kept.

-- ---------------------------------------------------------------- saved payees (beneficiaries)
-- Adding one needs the transaction PIN (W11); a customer only ever sees their own (W1);
-- the nickname is stored as AES-GCM ciphertext (W12).
CREATE TABLE IF NOT EXISTS beneficiaries (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users (id),
    payee_id    uuid NOT NULL REFERENCES users (id),
    nickname    text CHECK (char_length(nickname) <= 400),
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT beneficiary_once UNIQUE (user_id, payee_id),
    CONSTRAINT beneficiary_not_self CHECK (user_id <> payee_id)
);

ALTER TABLE beneficiaries ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'beneficiaries' AND policyname = 'beneficiaries_own') THEN
        CREATE POLICY beneficiaries_own ON beneficiaries
            USING (user_id = app_uid()) WITH CHECK (user_id = app_uid());
    END IF;
END $$;

GRANT SELECT, INSERT, DELETE ON beneficiaries TO wallet_app;
