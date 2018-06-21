PRAGMA foreign_keys = ON;

CREATE TABLE hidden_services (
	id integer PRIMARY KEY AUTOINCREMENT,
	link text
);

CREATE TABLE descriptors (
	PRIMARY KEY FOREIGN KEY(link_id) REFERENCES hidden_services(id),
	rendezvous_service_descriptor text,
	descriptor_id text,
	format_version text,
	permanent_key text,
	secret_id_part text,
	publication_time text,
	protocol_versions text,
	descriptor_signature text
);

CREATE TABLE descriptors_introduction_points (
	id integer PRIMARY KEY AUTOINCREMENT,
	FOREIGN KEY(link_id) REFERENCES hidden_services(id),
	introduction_point text,
	ip_address text,
	onion_port text,
	onion_key text,
	service_key text
);

-- CREATE TABLE service_info (
-- 	link_id integer,
-- 	service_type text,
-- 	service_description text,
-- 	service_state text check(name = "active" or name = "inactive" or name = "unknown")
-- );

-- CREATE TABLE device_info (
-- 	link_id integer,
-- 	os text,
-- 	port integer,
-- 	port_service_type text,
-- 	port_service_version text
-- );

-- CREATE TABLE device_info_snapshot (
-- 	link_id integer,
-- 	open_ports text,
-- 	snapshot_time timestamp
-- );

-- CREATE TABLE service_info_snapshot (
-- 	link_id integer,
-- 	descriptor_id integer,
-- 	introduction_points text,
-- 	snapshot_time timestamp
-- );
