-- name: exists_user?
-- returns a boolean stating if the user already exists
SELECT EXISTS (
SELECT email
FROM users
WHERE email = :email
);

-- name: create_user!
-- creates a new user record
INSERT INTO users
(email, password)
VALUES (:email, :password);


-- name: accounts_for_user
-- retrieve all accounts a user has access to and the associated rights
SELECT account_name, admin
FROM accounts_users
WHERE email = :email;

-- name: exists_account?
-- returns a boolean stating if the account already exists
SELECT EXISTS (
SELECT account_name
FROM accounts
WHERE account_name = :account_name);

-- name: create_account!
-- creates a new user record
INSERT INTO accounts
(account_name)
VALUES (:account_name)


-- name: give_access!
-- create the relationship between the user and the account, by default not admin
INSERT INTO accounts_users (account_name, email, admin)
VALUES (:account_name, :email, FALSE);


-- name: change_admin!
-- changes the rights for a account-user relationship
UPDATE accounts_users
SET admin = NOT admin
WHERE account_name = :account_name AND email = :email;


-- name: users_for_account
-- retrieve all users and their rights for a given account
SELECT email, admin
FROM accounts_users
WHERE account_name = :account_name;


-- name: get_password
-- retrieve a user password given the email
SELECT password FROM users
WHERE email = :email;


-- name: user_rights_for_account
-- returns a boolean that gives the right of a user to an account
SELECT admin
FROM accounts_users
WHERE email = :email AND account_name = :account_name;

-- name: create_retrieve_token!
-- self-explanatory - did not manage to create a nice ON CONFLICT condition - to be done
INSERT INTO retrieve_email_tokens (email, token, created_at)
VALUES (:email, :token, :created_at);


-- name: user_has_retrieve_token?
-- self-explanatory
SELECT created_at
FROM retrieve_email_tokens
WHERE email = :email;


-- name: update_retrieve_token!
-- self-explanatory
UPDATE retrieve_email_tokens
SET token = :token, created_at = :created_at
WHERE email = :email;


-- name: token_details_for_retrieve_email
-- self-explanatory
SELECT email, created_at
FROM retrieve_email_tokens
WHERE token = :token;

-- name: update_password!
-- self-explanatory
UPDATE users
SET password = :password
WHERE email = :email;