create table if not exists account (
		id uuid primary key,
		first_name varchar(100),
		last_name varchar(100),
		number serial,
		encrypted_password varchar(100),
		balance serial,
		created_at timestamp,
		username varchar(100),
    email varchar(100)
	)