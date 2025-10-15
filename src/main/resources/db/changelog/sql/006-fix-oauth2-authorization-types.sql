-- Align column types with Spring Authorization Server 1.5.x expectations (strings for attributes/metadata)
alter table if exists oauth2_authorization
  alter column attributes type text;

alter table if exists oauth2_authorization
  alter column authorization_code_metadata type text,
  alter column access_token_metadata type text,
  alter column oidc_id_token_metadata type text,
  alter column refresh_token_metadata type text,
  alter column user_code_metadata type text,
  alter column device_code_metadata type text;

alter table if exists oauth2_authorization
  alter column authorization_code_value type text,
  alter column access_token_value type text,
  alter column oidc_id_token_value type text,
  alter column refresh_token_value type text,
  alter column user_code_value type text,
  alter column device_code_value type text;
