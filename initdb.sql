-- Create table
create schema userapi;
create table users (
id BIGSERIAL PRIMARY KEY,
email text,
password text,
createdtime time,
updatetime time,
token text);
