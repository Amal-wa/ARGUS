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

# The `update` action (PUT/PATCH -- see request_action() in
# app/core/request_matching.py, which maps both to "update") had a rule but
# no test at all: coverage showed create/read/delete exercised and update
# not. Same shape as the read-permission gap above -- an untested
# role/action pair in an authorization policy is an unverified boundary, not
# a coverage statistic. /users stays admin-only for update too, same as
# every other action.

test_reader_put_documents_denied if {
	not rbac.allow with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "PUT", "route": "/documents/{document_id}", "action": "update"},
	}
}

test_editor_put_documents_allowed if {
	rbac.allow with input as {
		"identity": {"subject": "u1", "role": "editor"},
		"resource": {"http_method": "PUT", "route": "/documents/{document_id}", "action": "update"},
	}
}

test_admin_put_documents_allowed if {
	rbac.allow with input as {
		"identity": {"subject": "u1", "role": "admin"},
		"resource": {"http_method": "PUT", "route": "/documents/{document_id}", "action": "update"},
	}
}

test_editor_put_users_denied if {
	not rbac.allow with input as {
		"identity": {"subject": "u1", "role": "editor"},
		"resource": {"http_method": "PUT", "route": "/users/{user_id}", "action": "update"},
	}
}

test_admin_put_users_allowed if {
	rbac.allow with input as {
		"identity": {"subject": "u1", "role": "admin"},
		"resource": {"http_method": "PUT", "route": "/users/{user_id}", "action": "update"},
	}
}

# /monitoring/* is admin-only for every action, same as /users -- readers and
# editors must never reach the security dashboard's decision feed, risk
# timeline, or audit log, even though every route under it is a GET (a
# "read" action that the general rule below would otherwise grant to
# reader/editor too).

test_admin_get_monitoring_stats_allowed if {
	rbac.allow with input as {
		"identity": {"subject": "u1", "role": "admin"},
		"resource": {"http_method": "GET", "route": "/monitoring/stats", "action": "read"},
	}
}

test_admin_get_monitoring_audit_allowed if {
	rbac.allow with input as {
		"identity": {"subject": "u1", "role": "admin"},
		"resource": {"http_method": "GET", "route": "/monitoring/audit", "action": "read"},
	}
}

test_reader_get_monitoring_stats_denied if {
	not rbac.allow with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/monitoring/stats", "action": "read"},
	}
}

test_editor_get_monitoring_stats_denied if {
	not rbac.allow with input as {
		"identity": {"subject": "u1", "role": "editor"},
		"resource": {"http_method": "GET", "route": "/monitoring/stats", "action": "read"},
	}
}

test_reader_get_monitoring_decisions_denied if {
	not rbac.allow with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/monitoring/decisions", "action": "read"},
	}
}

test_editor_get_monitoring_risk_timeline_denied if {
	not rbac.allow with input as {
		"identity": {"subject": "u1", "role": "editor"},
		"resource": {"http_method": "GET", "route": "/monitoring/risk-timeline", "action": "read"},
	}
}
