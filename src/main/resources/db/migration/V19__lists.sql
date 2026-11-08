-- ─────────────────────────────────────────────────────────────────────────────
-- List management, job 1: lists, contacts, list members, parts, the import
-- staging table and the LISTS permission.
--
-- A list is one uploaded file (from the PC or a Google Drive link) with the
-- old app's fields: name, ESP, country, vertical, remove duplicates (yes/no)
-- and split by N. Its addresses are list_members rows; the same address in
-- many lists is ONE contacts row (normalised: trimmed + lowercased). Each
-- member keeps the file row's original columns (jsonb array, in the order of
-- lists.columns) so exports can give them back next to a validation result.
-- "Split by N" cuts the list into parts of N members (list_parts), each of
-- which can be validated on its own.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE user_permissions DROP CONSTRAINT chk_user_permissions_module;
ALTER TABLE user_permissions ADD CONSTRAINT chk_user_permissions_module CHECK (module IN ('DASHBOARD', 'CONTACTS',
    'VALIDATION', 'SERVERS', 'MTA', 'SEGMENTS', 'SUPPRESSION', 'USERS', 'ACTIVITY_LOG', 'BACKUPS', 'SETTINGS',
    'DNS', 'LISTS'));

-- Lists used to be shown under the Contacts permission (M2): whoever had a
-- Contacts action gets the same Lists action, so nobody loses a page.
INSERT INTO user_permissions (user_id, module, action, granted_at, granted_by)
SELECT user_id, 'LISTS', action, now(), granted_by FROM user_permissions
WHERE module = 'CONTACTS' AND action IN ('VIEW', 'CREATE', 'EDIT', 'DELETE', 'EXPORT')
ON CONFLICT DO NOTHING;

-- One row per email address MasterDB holds, whatever list it came from.
CREATE TABLE contacts (
    id          BIGINT        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- trimmed + lowercased (the domain also in its ASCII/punycode form)
    email       VARCHAR(254)  NOT NULL,
    domain      VARCHAR(253)  NOT NULL,
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT uq_contacts_email UNIQUE (email)
);

CREATE INDEX idx_contacts_domain ON contacts (domain);

CREATE TABLE lists (
    id                  BIGINT        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id           UUID          NOT NULL DEFAULT gen_random_uuid(),
    name                VARCHAR(255)  NOT NULL,
    esp                 VARCHAR(255)  NOT NULL DEFAULT '',
    country             VARCHAR(255)  NOT NULL DEFAULT '',
    vertical            VARCHAR(255)  NOT NULL DEFAULT '',
    remove_duplicates   BOOLEAN       NOT NULL,
    -- 0 = one part (no split)
    split_size          INT           NOT NULL DEFAULT 0,
    -- FILE (from the PC) or DRIVE (a Google Drive link)
    source              VARCHAR(10)   NOT NULL,
    -- the file name, or the Drive link as typed
    source_name         VARCHAR(2000) NOT NULL,
    -- UPLOADING → MAPPING (choose the email column) → QUEUED → IMPORTING → READY;
    -- DOWNLOADING instead of UPLOADING for Drive; FAILED with a message.
    status              VARCHAR(12)   NOT NULL,
    message             VARCHAR(1000),
    -- the uploaded file: bytes announced (NULL = not known yet, Drive without a length) and acknowledged
    file_size           BIGINT,
    received            BIGINT        NOT NULL DEFAULT 0,
    -- column mapping, chosen after the upload
    delimiter           VARCHAR(4),
    has_header          BOOLEAN,
    email_column        INT,
    -- the header cells (or "Column 1", …), a jsonb array of strings
    columns             JSONB,
    -- import progress (bytes of the file read, then rows saved) and report
    import_phase        VARCHAR(12),
    import_done         BIGINT        NOT NULL DEFAULT 0,
    import_total        BIGINT        NOT NULL DEFAULT 0,
    total_lines         BIGINT        NOT NULL DEFAULT 0,
    invalid             BIGINT        NOT NULL DEFAULT 0,
    duplicates          BIGINT        NOT NULL DEFAULT 0,
    in_other_lists      BIGINT        NOT NULL DEFAULT 0,
    records             INT           NOT NULL DEFAULT 0,
    parts               INT           NOT NULL DEFAULT 0,
    import_started_at   TIMESTAMPTZ,
    imported_at         TIMESTAMPTZ,
    -- latest result per member over every validation job of this list (refreshed when a job stops or finishes)
    validation_counts   JSONB,
    validated_at        TIMESTAMPTZ,
    actor_public_id     UUID,
    actor_label         VARCHAR(254),
    created_at          TIMESTAMPTZ   NOT NULL,
    updated_at          TIMESTAMPTZ   NOT NULL,
    CONSTRAINT uq_lists_public_id UNIQUE (public_id),
    CONSTRAINT chk_lists_source CHECK (source IN ('FILE', 'DRIVE')),
    CONSTRAINT chk_lists_status CHECK (status IN ('UPLOADING', 'DOWNLOADING', 'MAPPING', 'QUEUED', 'IMPORTING',
        'READY', 'FAILED')),
    CONSTRAINT chk_lists_split CHECK (split_size >= 0),
    CONSTRAINT chk_lists_received CHECK (received >= 0 AND (file_size IS NULL OR received <= file_size))
);

CREATE INDEX idx_lists_created ON lists (created_at DESC, id DESC);
CREATE INDEX idx_lists_status ON lists (status);

-- The parts of a list ("split by N"); a list that is not split has one part.
CREATE TABLE list_parts (
    id         BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id  UUID    NOT NULL DEFAULT gen_random_uuid(),
    list_id    BIGINT  NOT NULL REFERENCES lists (id) ON DELETE CASCADE,
    part_no    INT     NOT NULL,
    records    INT     NOT NULL,
    first_seq  INT     NOT NULL,
    last_seq   INT     NOT NULL,
    CONSTRAINT uq_list_parts_public_id UNIQUE (public_id),
    CONSTRAINT uq_list_parts UNIQUE (list_id, part_no)
);

-- One address of a list, in file order (seq 1..records). A list that keeps
-- duplicates has several members with the same contact.
CREATE TABLE list_members (
    id          BIGINT        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    list_id     BIGINT        NOT NULL REFERENCES lists (id) ON DELETE CASCADE,
    seq         INT           NOT NULL,
    part_no     INT           NOT NULL,
    contact_id  BIGINT        NOT NULL REFERENCES contacts (id),
    -- the address as written in the file (trimmed, domain lowercased)
    email       VARCHAR(254)  NOT NULL,
    -- the file row's cells, in the order of lists.columns (NULL for a one-column file)
    fields      JSONB
);

CREATE UNIQUE INDEX uq_list_members_seq ON list_members (list_id, seq);
CREATE INDEX idx_list_members_part ON list_members (list_id, part_no, seq);
CREATE INDEX idx_list_members_contact ON list_members (contact_id, list_id);

-- Staging for an import: the file's valid rows are COPYed here, then moved
-- into contacts and list_members in chunks. UNLOGGED (fast, not in the WAL):
-- after a crash it may be empty, which is fine, because an interrupted import
-- always starts again from the file.
CREATE UNLOGGED TABLE list_import_rows (
    list_id  BIGINT        NOT NULL,
    seq      INT           NOT NULL,
    email    VARCHAR(254)  NOT NULL,
    norm     VARCHAR(254)  NOT NULL,
    domain   VARCHAR(253)  NOT NULL,
    fields   JSONB
);

CREATE INDEX idx_list_import_rows_seq ON list_import_rows (list_id, seq);
CREATE INDEX idx_list_import_rows_norm ON list_import_rows (list_id, norm, seq);
