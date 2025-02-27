package vault

#
# Obtain secrets from Opa's service secret store in Vault
#
import rego.v1

import data.idp.user_key
import data.store_token.token as vault_token

# paths are the paths authorized for methods, used by permissions.rego
paths := http.send({"method": "get", "url": "VAULT_URL/v1/opa/paths", "headers": {"X-Vault-Token": vault_token}}).body.data.paths

# groups are site-wide authorizations, used by permissions.rego and authz.rego
groups := http.send({"method": "get", "url": "VAULT_URL/v1/opa/groups", "headers": {"X-Vault-Token": vault_token}}).body.data

all_studies := http.send({"method": "get", "url": "VAULT_URL/v1/opa/studies", "headers": {"X-Vault-Token": vault_token}}).body.data.studies

study_auths[p] := study if {
	some p in all_studies
	study := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1/opa/studies", p]), "headers": {"X-Vault-Token": vault_token}}).body.data[p]
}

user_index := http.send({"method": "get", "url": "VAULT_URL/v1/opa/users/index", "headers": {"X-Vault-Token": vault_token}, "raise_error": false}).body.data

user_id := user_index[user_key]

# check to see if the user is authorized for any other studies via DACs
user_auth := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1/opa/users", user_id]), "headers": {"X-Vault-Token": vault_token}, "raise_error": false})

default user_studies := {}

user_studies := user_auth.body.data.study_authorizations if {
	user_auth.status_code = 200
}
