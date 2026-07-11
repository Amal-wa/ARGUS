package authz.rbac

default allow := false

allow if {
    input.resource.action == "read"
    input.identity.role == "reader"
}

allow if {
    input.resource.action == "create"
    input.identity.role in {"editor", "admin"}
}

allow if {
    input.resource.action == "update"
    input.identity.role in {"editor", "admin"}
}

allow if {
    input.resource.action == "delete"
    input.identity.role == "admin"
}