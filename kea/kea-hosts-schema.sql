-- Kea DHCP hosts table for PostgreSQL backend
CREATE TABLE IF NOT EXISTS hosts (
    host_id SERIAL PRIMARY KEY,
    dhcp_identifier BYTEA NOT NULL,
    dhcp_identifier_type SMALLINT NOT NULL,
    dhcp4_subnet_id INTEGER NULL,
    dhcp6_subnet_id INTEGER NULL,
    ipv4_address BIGINT NULL,
    hostname VARCHAR(255) NULL,
    dhcp4_client_classes VARCHAR(255) NULL,
    dhcp6_client_classes VARCHAR(255) NULL,
    dhcp4_next_server BIGINT NULL,
    dhcp4_server_hostname VARCHAR(64) NULL,
    dhcp4_boot_file_name VARCHAR(128) NULL,
    user_context TEXT NULL,
    auth_key VARCHAR(16) NULL
);

CREATE INDEX IF NOT EXISTS hosts_dhcp4_subnet_id ON hosts (dhcp4_subnet_id);
CREATE INDEX IF NOT EXISTS hosts_dhcp_identifier ON hosts (dhcp_identifier, dhcp_identifier_type);
