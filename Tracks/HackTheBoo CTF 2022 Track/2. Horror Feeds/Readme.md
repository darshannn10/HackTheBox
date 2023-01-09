## Challenge Description
An unknown entity has taken over every screen worldwide and is broadcasting this haunted feed that introduces paranormal activity to random internet-accessible CCTV devices. Could you take down this streaming service?

We have the source code of a Python application.

In the `entrypoint.sh` file, we see that the application creates a `MySQL/MariaDB` database and populates the following data.

``bash
┌──(darshan㉿kali)-[~/…/HackTheBox/HacktheBoo-ctf-2022/Horror-Feeds/web_horror_feeds]
└─$ cat entrypoint.sh       
#!/bin/ash

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
