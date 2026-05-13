#!/bin/bash
set -e

psql "$DATABASE_URL" -c "DROP TABLE IF EXISTS acl_rule_allocations;"
