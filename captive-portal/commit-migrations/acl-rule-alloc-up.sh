#!/bin/bash
set -e

psql "$DATABASE_URL" -c "
CREATE TABLE IF NOT EXISTS acl_rule_allocations (
    ip_address  TEXT        NOT NULL PRIMARY KEY,
    rule_num    INTEGER     NOT NULL,
    allocated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT acl_rule_allocations_rule_num_unique UNIQUE (rule_num),
    CONSTRAINT acl_rule_allocations_rule_num_range  CHECK (rule_num BETWEEN 1 AND 19999)
);
CREATE INDEX IF NOT EXISTS idx_acl_rule_allocations_rule_num
    ON acl_rule_allocations (rule_num);
"
