create table if not exists users (
  username varchar(50) primary key,
  password varchar(100) not null,
  enabled boolean not null
);
create table if not exists authorities (
  username varchar(50) not null references users(username),
  authority varchar(50) not null,
  constraint ix_auth unique (username, authority)
);