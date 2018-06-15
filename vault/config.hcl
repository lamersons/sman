storage "file" {
  path = "/home/kali/Repos/sman/vault/db.data"
}

listener "tcp" {
 address = "localhost:8200"
 tls_disable = 1
 tls_cert_file = "/home/kali/Repos/sman/vault/vault.crt"
 tls_key_file = "/home/kali/Repos/sman/vault/vault.key"
}
