# Simple API Access Key issuer, Validate aes-gcm-256

![made-with-python][made-with-python]
![Python Versions][pyversion-button]
![Hits][hits-button]

[pyversion-button]: https://img.shields.io/pypi/pyversions/Markdown.svg
[made-with-python]: https://img.shields.io/badge/Made%20with-Python-1f425f.svg
[hits-button]: https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fpassword123456%2Faccess-key-issuer-validator-aes-gcm&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=false

A simple practical Python code for generating, encrypting, and validating access keys using AES-256-GCM.

***

## Example

### Original Text Access Key

```json
{
    "iss": "keyman",
    "app_id": "myapp",
    "iat": 1725517483,
    "exp": 1733293483,
    "allow_ips": ["192.168.1.1", "192.168.1.2"]
}
```

- `iss`: Issuer of the access key.
- `app_id`: Application or service identifier.
- `iat`: Issue time (Unix timestamp).
- `exp`: Expiration time (Unix timestamp).
- `allow_ips`: List of IP addresses that are allowed to use this access key.

The access key is validated by checking the expiration time and the allowed IP addresses.


### Output

```python
Original Text Access Key: {'iss': 'keyman', 'app_id': 'myapp', 'iat': 1725517483, 'exp': 1733293483, 'allow_ips': ['192.168.1.1', '192.168.1.2']}

Passphrase Key: Z+yX1m7ezh7WK/74UaC6z3o7nKkQfdTlz8rBxtx4qgw=

Encrypted Access Key: USwxi7NX8aXTRuY3CggaF3PxzsgBzNka7SiKc5D0LZ9BtN/yxXXpsaoqkVFZjlEDuIq2kZu9Sq/Hh7j1cfcfSrE4Pu4P4Ed+9c+U6he5kklXBWkwjS72NbTynL5yket3vQ7rdEWEN0ZhAIuBJ+B/bUVSGhjWGlQ0yCYRF5lOE80HMyf0BnR6tYkWYPyCEti5rgJiXxV3a6vJ

Encrypted Access Key Length: 204

Decrypted Access Key: {"iss": "keyman", "app_id": "myapp", "iat": 1725517483, "exp": 1733293483, "allow_ips": ["192.168.1.1", "192.168.1.2"]}

Access key Expiration: 1733293483
 - Key is valid

Access Key Allowed: ['192.168.1.1', '192.168.1.2']
 - Remote address 192.168.10.1 is not allowed
```

## Recommendation
- In this code, `key.db` is used locally as a database `for demonstration purposes.` 
- This is not the recommended implementation method. Store keys in a Key Management Service (KMS) or a proper database.
- However, if you still intend to use the current code (with key.db), make sure to add code that encrypts the entire key.db file. When running the code, store the decryption key in a memory

  
