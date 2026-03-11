# ASMB-iKVM-Brute-Force

A **multi-threaded brute force tool** designed to test authentication security of **ASMB server management interfaces**.

# Requirements

* Python 3.x

### Python Libraries

```
requests
colorama
beautifulsoup4
````

Install dependencies:

```bash
pip install -r requirements.txt
```


# Usage

```
usage: main.py [-h] -s SERVER [-u USERS] [-P PASSWORD]
               [-c CREDENTIALS] [-S SCHEME]
               [-t TIMEOUT] [-T THREADS] [-w WRITE]

ASMB iKVM Brute Force
```

### Arguments

| Argument              | Description                                                    |
| --------------------- | -------------------------------------------------------------- |
| `-s`, `--server`      | Target server(s) separated by comma or file containing servers |
| `-u`, `--users`       | Username list separated by comma or file                       |
| `-P`, `--password`    | Password list separated by comma or file                       |
| `-c`, `--credentials` | File containing credentials (`user:password`)                  |
| `-S`, `--scheme`      | HTTP scheme (`http` or `https`)                                |
| `-t`, `--timeout`     | Request timeout                                                |
| `-T`, `--threads`     | Number of brute force threads                                  |
| `-w`, `--write`       | CSV output file for successful logins                          |
