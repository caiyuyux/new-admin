CREATE TABLE users
(email VARCHAR(50) PRIMARY KEY,
 password VARCHAR(100)
 );

CREATE TABLE accounts
(account_name VARCHAR(30)  PRIMARY KEY
);

CREATE TABLE accounts_users
(account_name VARCHAR REFERENCES accounts,
 email VARCHAR REFERENCES users,
 admin BOOLEAN
 );

CREATE TABLE retrieve_email_tokens
 (email VARCHAR UNIQUE REFERENCES users,
  token VARCHAR,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);

