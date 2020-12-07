# Vault export
Exports all vault kv secrets as json file and encrypts it using openssl.

## Prerequiresites
Vault cli installed.  
Be logged via vault cli.

## Usage
```
./vault-export.php 
```

## Options  
-d print some debug infos  
-p encrypt password file

Example : 
```
./vault-export.php [-d] [-p password-file-path]
```