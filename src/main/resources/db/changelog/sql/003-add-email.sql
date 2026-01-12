alter table if exists users
  add column if not exists email varchar(255);

create unique index if not exists ux_users_email on users (email);

