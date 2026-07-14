package authz.rbac

default allow := false

# /users is an admin-only concern for every action, including read -- user
# listings expose emails and roles, and account provisioning/deactivation must
# not be reachable via the general action-based rules below (an editor's
# "create" grant would otherwise let them POST /users and provision accounts --
# a real privilege escalation). This must be checked ahead of, and independently
# of, the general rules.
users_route if {
    startswith(input.resource.route, "/users")
}

allow if {
    users_route
    input.identity.role == "admin"
}

allow if {
    not users_route
    input.resource.action == "read"
    input.identity.role in {"reader", "editor", "admin"}
}

allow if {
    not users_route
    input.resource.action == "create"
    input.identity.role in {"editor", "admin"}
}

allow if {
    not users_route
    input.resource.action == "update"
    input.identity.role in {"editor", "admin"}
}

allow if {
    not users_route
    input.resource.action == "delete"
    input.identity.role == "admin"
}
