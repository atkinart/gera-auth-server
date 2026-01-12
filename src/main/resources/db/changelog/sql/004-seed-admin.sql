-- Seed default admin user (bcrypt password: "admin") and role
insert into users(username, password, enabled, email)
values ('admin', '{noop}admin', true, 'admin@example.com')
on conflict (username) do nothing;

insert into authorities(username, authority)
values ('admin', 'ROLE_ADMIN')
on conflict do nothing;
