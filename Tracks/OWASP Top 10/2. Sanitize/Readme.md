# DESCRIPTION
Can you escape the query context and log in as admin at my super secure login page?

## Analysis
First we're encountered with a signin form:
![s1](https://user-images.githubusercontent.com/87711310/211148772-a1dab8d4-e6b0-4260-b1c2-97898273548b.png)

Let's try some default creds, admin and admin.

Below, the query run on the database is shown; this seems like a clear example of `SQL injection`.

![s2](https://user-images.githubusercontent.com/87711310/211148768-0e3c93a2-cb13-40fa-ae90-15e6c1bf5370.png)

# Exploitation
Ultimately, we want to try and log in as a user. To do this, we can try to inject our own SQL.

We know the payload looks like the following:

```sql
select * from users where username = '<username>' AND password = '<password>';
```

We want to trick this into always returning a user, and to do this we'll inject a clause that's `always` true, such as 1=1.

```sql
admin' OR 1=1
```

That will make the query equal to the following:

```sql
select * from users where username = 'admin' OR 1=1 AND password = 'password';
```
So here, it'll compare the username to admin, and if it's not the same the check will `still` pass because 1=1. However, there's a small issue with the password still being wrong. To bypass this check, we'll make everything after our injection a `comment` so that the databse ignores it:

```sql
admin' OR 1=1;--
```

That would make the query be:
```sql
select * from users where username = 'admin' OR 1=1;-- AND password = 'password';
```

As you can see, the username will always be correct due to the 1=1 and the password check is commented out! Let's try it.

We still have to input a password because some javascript checks to make sure it's there, but we can fill that with any rubbish. And we get the flag!

![s3](https://user-images.githubusercontent.com/87711310/211148770-ef2959c5-f805-443c-b7a2-0c7b36fc832c.png)
