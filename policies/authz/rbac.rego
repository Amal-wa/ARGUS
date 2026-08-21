# METADATA
# description: RBAC input shape is checked against policies/schemas/input.json via `opa check --schema`.
# schemas:
#   - input: schema["input"]
package authz.rbac

default allow := false

# /users is an admin-only concern for every action, including read -- user
# listings expose emails and roles, and account provisioning/deactivation must
# not be reachable via the general action-based rules below (an editor's
# "create" grant would otherwise let them POST /users and provision accounts --
# a real privilege escalation). This must be checked ahead of, and independently
# of, the general rules.
#
# Split into an exact match and a "/users/"-prefixed match (rather than a bare
# startswith(route, "/users")) so a future unrelated route sharing the prefix
# (e.g. "/userscount") can't silently fall into this admin-only bucket.
users_route if {
	input.resource.route == "/users"
}

users_route if {
	startswith(input.resource.route, "/users/")
}

# /monitoring/* is the security-dashboard read surface: decision feeds, risk
# timelines, and the audit log. Admin-only for every action (even though every
# route under it is a GET/read today) -- same reasoning as /users: this must
# not fall through to the general read rule below, which would hand it to
# readers/editors too. Same exact/prefix split as users_route above, same reason.
monitoring_route if {
	input.resource.route == "/monitoring"
}

monitoring_route if {
	startswith(input.resource.route, "/monitoring/")
}

allow if {
	users_route
	input.identity.role == "admin"
}

allow if {
	monitoring_route
	input.identity.role == "admin"
}

# Shared guard for the general action-based rules below -- extracted so a new
# action rule can't be added there without it (previously each rule repeated
# both negations inline).
general_route if {
	not users_route
	not monitoring_route
}

write_roles := {"editor", "admin"}

allow if {
	general_route
	input.resource.action == "read"
	input.identity.role in {"reader", "editor", "admin"}
}

allow if {
	general_route
	input.resource.action == "create"
	input.identity.role in write_roles
}

allow if {
	general_route
	input.resource.action == "update"
	input.identity.role in write_roles
}

allow if {
	general_route
	input.resource.action == "delete"
	input.identity.role == "admin"
}
