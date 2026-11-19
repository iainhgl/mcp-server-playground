# OpenBao stands in for AWS KMS (transit) + Secrets Manager (KV). SPEC §1.1.
# Not dev mode: storage persists and the server starts sealed, so the
# transit key protecting the token vault survives restarts.
# Integrated Raft storage (single node). OpenBao 2.x has removed `file`.
storage "raft" {
  path    = "/openbao/file"
  node_id = "openbao-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr      = "http://openbao:8200"
cluster_addr  = "http://openbao:8201"
ui            = true
disable_mlock = true
