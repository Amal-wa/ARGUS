package authz.rbac_test

import data.authz.rbac

# Section 3.a: /users is admin-only for every action, including read.

test_editor_post_users_denied if {
    not rbac.allow with input as {
        "identity": {"subject": "u1", "role": "editor"},
        "resource": {"http_method": "POST", "route": "/users", "action": "create"},
    }
}

test_editor_get_users_denied if {
    not rbac.allow with input as {
        "identity": {"subject": "u1", "role": "editor"},
        "resource": {"http_method": "GET", "route": "/users", "action": "read"},
    }
}

test_reader_get_users_denied if {
    not rbac.allow with input as {
        "identity": {"subject": "u1", "role": "reader"},
        "resource": {"http_method": "GET", "route": "/users/{user_id}", "action": "read"},
    }
}

test_admin_get_users_allowed if {
    rbac.allow with input as {
        "identity": {"subject": "u1", "role": "admin"},
        "resource": {"http_method": "GET", "route": "/users", "action": "read"},
    }
}

test_admin_post_users_allowed if {
    rbac.allow with input as {
        "identity": {"subject": "u1", "role": "admin"},
        "resource": {"http_method": "POST", "route": "/users", "action": "create"},
    }
}

test_admin_delete_users_allowed if {
    rbac.allow with input as {
        "identity": {"subject": "u1", "role": "admin"},
        "resource": {"http_method": "DELETE", "route": "/users/{user_id}", "action": "delete"},
    }
}

# No regression on the other routes.

test_editor_post_documents_still_allowed if {
    rbac.allow with input as {
        "identity": {"subject": "u1", "role": "editor"},
        "resource": {"http_method": "POST", "route": "/documents", "action": "create"},
    }
}

test_reader_get_documents_allowed if {
    rbac.allow with input as {
        "identity": {"subject": "u1", "role": "reader"},
        "resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
    }
}

test_reader_post_documents_denied if {
    not rbac.allow with input as {
        "identity": {"subject": "u1", "role": "reader"},
        "resource": {"http_method": "POST", "route": "/documents", "action": "create"},
    }
}

# The read-permission gap fixed alongside the /users escalation: editor and
# admin previously had NO read grant at all on non-/users routes.

test_editor_get_documents_allowed if {
    rbac.allow with input as {
        "identity": {"subject": "u1", "role": "editor"},
        "resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
    }
}

test_admin_get_documents_allowed if {
    rbac.allow with input as {
        "identity": {"subject": "u1", "role": "admin"},
        "resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
    }
}

test_editor_delete_documents_denied if {
    not rbac.allow with input as {
        "identity": {"subject": "u1", "role": "editor"},
        "resource": {"http_method": "DELETE", "route": "/documents/{document_id}", "action": "delete"},
    }
}

test_admin_delete_documents_allowed if {
    rbac.allow with input as {
        "identity": {"subject": "u1", "role": "admin"},
        "resource": {"http_method": "DELETE", "route": "/documents/{document_id}", "action": "delete"},
    }
}
