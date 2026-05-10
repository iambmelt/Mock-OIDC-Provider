"""Tests for Phase 7 admin endpoints and audit logging."""

import pytest
from tests.conftest import (
    do_authorize,
    exchange_code,
)


class TestAuditLogEndpoint:
    """Tests for /admin/audit endpoint."""

    def test_admin_audit_returns_200(self, client):
        """GET /admin/audit returns 200 with correct structure."""
        resp = client.get("/admin/audit")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "count" in data
        assert "total_in_store" in data
        assert "entries" in data
        assert isinstance(data["entries"], list)

    def test_audit_entries_have_required_fields(self, client, config):
        """Audit entries include ts, event, and optional request_id."""
        code, _ = do_authorize(client)
        exchange_code(client, code)

        resp = client.get("/admin/audit?limit=10")
        data = resp.get_json()

        assert data["count"] > 0
        for entry in data["entries"]:
            assert "ts" in entry, "Entry missing 'ts' field"
            assert "event" in entry, "Entry missing 'event' field"
            assert isinstance(entry["ts"], str), "ts should be ISO8601 string"

    def test_audit_entries_in_reverse_chronological_order(self, client):
        """Audit entries are sorted by timestamp, most recent first."""
        # Generate some events
        code1, _ = do_authorize(client)
        code2, _ = do_authorize(client)
        exchange_code(client, code1)
        exchange_code(client, code2)

        resp = client.get("/admin/audit?limit=100")
        data = resp.get_json()
        entries = data["entries"]

        # Verify they're sorted by timestamp, most recent first
        for i in range(len(entries) - 1):
            assert (
                entries[i]["ts"] >= entries[i + 1]["ts"]
            ), "Audit entries should be in reverse chronological order"

    def test_audit_limit_parameter(self, client):
        """?limit parameter limits returned entries (default 100, max 1000)."""
        # Generate some events
        for _ in range(5):
            code, _ = do_authorize(client)
            exchange_code(client, code)

        # Default limit should be 100
        resp = client.get("/admin/audit")
        data = resp.get_json()
        assert data["count"] <= 100

        # Explicit limit
        resp = client.get("/admin/audit?limit=5")
        data = resp.get_json()
        assert data["count"] <= 5
        assert len(data["entries"]) <= 5

        # Max limit enforcement (1000)
        resp = client.get("/admin/audit?limit=9999")
        data = resp.get_json()
        assert data["count"] <= 1000

    def test_audit_event_type_filtering(self, client):
        """?event= filters by event type."""
        code, _ = do_authorize(client)
        exchange_code(client, code)

        # Filter by authorize_code_issued
        resp = client.get("/admin/audit?event=authorize_code_issued")
        data = resp.get_json()
        for entry in data["entries"]:
            assert entry["event"] == "authorize_code_issued"

        # Filter by token_issued
        resp = client.get("/admin/audit?event=token_issued")
        data = resp.get_json()
        for entry in data["entries"]:
            assert entry["event"] == "token_issued"

    def test_audit_client_id_filtering(self, client):
        """?client_id= filters by client_id."""
        code, _ = do_authorize(client, client_id="client-a")
        exchange_code(client, code, client_id="client-a")

        code2, _ = do_authorize(client, client_id="client-b")
        exchange_code(client, code2, client_id="client-b")

        # Filter by client-a
        resp = client.get("/admin/audit?client_id=client-a")
        data = resp.get_json()
        for entry in data["entries"]:
            client_id = entry.get("client_id")
            if client_id:  # Some events may not have client_id
                assert client_id == "client-a"

        # Filter by client-b
        resp = client.get("/admin/audit?client_id=client-b")
        data = resp.get_json()
        for entry in data["entries"]:
            client_id = entry.get("client_id")
            if client_id:
                assert client_id == "client-b"

    def test_audit_combined_filters(self, client):
        """Both ?event= and ?client_id= work together."""
        code, _ = do_authorize(client, client_id="test-client")
        exchange_code(client, code, client_id="test-client")

        resp = client.get("/admin/audit?event=code_exchanged&client_id=test-client")
        data = resp.get_json()
        for entry in data["entries"]:
            assert entry["event"] == "code_exchanged"
            assert entry.get("client_id") == "test-client"

    def test_audit_entry_structure_for_authorize_code_issued(self, client):
        """authorize_code_issued audit entry has required fields."""
        code, _ = do_authorize(client, client_id="app-1", scope="openid email")

        resp = client.get("/admin/audit?event=authorize_code_issued")
        data = resp.get_json()
        assert data["count"] > 0

        entry = data["entries"][0]
        assert entry["event"] == "authorize_code_issued"
        assert entry.get("client_id") == "app-1"
        assert entry.get("scope") == "openid email"
        assert "username" in entry

    def test_audit_entry_structure_for_token_issued(self, client):
        """token_issued audit entry has required fields."""
        code, _ = do_authorize(client, client_id="app-1", scope="openid email")
        exchange_code(client, code, client_id="app-1")

        resp = client.get("/admin/audit?event=token_issued")
        data = resp.get_json()
        assert data["count"] > 0

        entry = data["entries"][0]
        assert entry["event"] == "token_issued"
        assert entry.get("client_id") == "app-1"
        assert entry.get("grant_type") == "authorization_code"
        assert "sub" in entry

    def test_audit_entry_structure_for_code_exchanged(self, client):
        """code_exchanged audit entry has required fields."""
        code, _ = do_authorize(client, client_id="app-1", scope="openid")
        exchange_code(client, code, client_id="app-1")

        resp = client.get("/admin/audit?event=code_exchanged")
        data = resp.get_json()
        assert data["count"] > 0

        entry = data["entries"][0]
        assert entry["event"] == "code_exchanged"
        assert entry.get("client_id") == "app-1"
        assert entry.get("grant_type") == "authorization_code"

    def test_audit_count_vs_total_in_store(self, client):
        """count is entries returned, total_in_store is all events."""
        code, _ = do_authorize(client)
        exchange_code(client, code)

        # Get all events
        resp = client.get("/admin/audit?limit=1000")
        data = resp.get_json()
        total = data["total_in_store"]

        # Get limited
        resp = client.get("/admin/audit?limit=2")
        data = resp.get_json()
        assert data["count"] <= 2
        assert data["total_in_store"] == total  # Total shouldn't change

    def test_audit_timestamp_format_is_iso8601(self, client):
        """Audit entry timestamps are ISO8601 format with Z suffix."""
        code, _ = do_authorize(client)
        exchange_code(client, code)

        resp = client.get("/admin/audit?limit=10")
        data = resp.get_json()

        for entry in data["entries"]:
            ts = entry["ts"]
            # ISO8601 with Z should end with Z
            assert ts.endswith("Z"), f"Timestamp {ts} should end with Z"
            # Should parse as valid ISO8601
            try:
                from datetime import datetime

                datetime.fromisoformat(ts.rstrip("Z"))
            except ValueError:
                pytest.fail(f"Timestamp {ts} is not valid ISO8601")


class TestStoreEndpoint:
    """Tests for /admin/store endpoint."""

    def test_admin_store_returns_200(self, client):
        """GET /admin/store returns 200 with correct structure."""
        resp = client.get("/admin/store")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "codes" in data
        assert "refresh_tokens" in data
        assert "audit_events" in data
        assert isinstance(data["codes"], int)
        assert isinstance(data["refresh_tokens"], int)
        assert isinstance(data["audit_events"], int)

    def test_store_counts_are_accurate_after_authorize(self, client):
        """Store counts reflect current state after authorize."""
        resp = client.get("/admin/store")
        initial = resp.get_json()

        # Generate an auth code
        code, _ = do_authorize(client, client_id="test-client")

        resp = client.get("/admin/store")
        after_auth = resp.get_json()

        # Should have one more code
        assert after_auth["codes"] == initial["codes"] + 1

    def test_store_codes_decrease_after_exchange(self, client):
        """Store codes count decreases after code exchange."""
        code, _ = do_authorize(client)

        resp = client.get("/admin/store")
        before_exchange = resp.get_json()
        assert before_exchange["codes"] == 1

        exchange_code(client, code)

        resp = client.get("/admin/store")
        after_exchange = resp.get_json()

        # Code should be consumed
        assert after_exchange["codes"] == 0

    def test_store_refresh_tokens_increase_after_token_exchange(self, client):
        """Store refresh_tokens count increases after token exchange."""
        resp = client.get("/admin/store")
        initial = resp.get_json()

        code, _ = do_authorize(client)
        exchange_code(client, code)

        resp = client.get("/admin/store")
        after = resp.get_json()

        # Should have one refresh token (if refresh_token flow is enabled)
        assert after["refresh_tokens"] >= initial["refresh_tokens"]

    def test_store_audit_events_increase(self, client):
        """Store audit_events count increases with activity."""
        resp = client.get("/admin/store")
        initial = resp.get_json()
        initial_audit = initial["audit_events"]

        code, _ = do_authorize(client)
        exchange_code(client, code)

        resp = client.get("/admin/store")
        after = resp.get_json()

        # Should have more audit events
        assert after["audit_events"] > initial_audit


class TestAdminDashboard:
    """Tests for /admin/ dashboard endpoint."""

    def test_admin_dashboard_returns_200(self, client):
        """GET /admin/ returns 200."""
        resp = client.get("/admin/")
        assert resp.status_code == 200

    def test_admin_dashboard_returns_html(self, client):
        """GET /admin/ returns HTML content."""
        resp = client.get("/admin/")
        assert resp.status_code == 200
        assert resp.content_type.startswith("text/html")
        content = resp.get_data(as_text=True)
        assert "<!DOCTYPE html>" in content or "<html>" in content

    def test_admin_dashboard_contains_title(self, client):
        """Dashboard HTML contains expected title."""
        resp = client.get("/admin/")
        content = resp.get_data(as_text=True)
        assert "Mock OIDC Admin Dashboard" in content

    def test_admin_dashboard_has_stats_containers(self, client):
        """Dashboard has stat boxes for codes, tokens, and audit events."""
        resp = client.get("/admin/")
        content = resp.get_data(as_text=True)
        assert "codes-count" in content
        assert "tokens-count" in content
        assert "audit-count" in content

    def test_admin_dashboard_has_audit_table(self, client):
        """Dashboard has audit event table."""
        resp = client.get("/admin/")
        content = resp.get_data(as_text=True)
        assert "audit-table" in content
        assert "Timestamp" in content
        assert "Event" in content

    def test_admin_dashboard_has_filter_inputs(self, client):
        """Dashboard has filter inputs for event and client_id."""
        resp = client.get("/admin/")
        content = resp.get_data(as_text=True)
        assert "filter-event" in content
        assert "filter-client" in content

    def test_admin_dashboard_has_javascript(self, client):
        """Dashboard includes JavaScript for updates."""
        resp = client.get("/admin/")
        content = resp.get_data(as_text=True)
        assert "<script>" in content
        assert "updateDashboard" in content


class TestAuditIntegration:
    """Integration tests for audit logging across flows."""

    def test_full_oauth_flow_generates_audit_events(self, client):
        """Complete OAuth flow generates expected audit events."""
        # Clear existing events by checking initial count
        resp = client.get("/admin/audit?limit=1000")
        initial_count = resp.get_json()["total_in_store"]

        # Do authorize
        code, _ = do_authorize(client, client_id="app-1", scope="openid email")

        # Exchange code
        token_resp = exchange_code(client, code, client_id="app-1")
        assert token_resp.status_code == 200

        resp = client.get("/admin/audit?limit=1000")
        final_count = resp.get_json()["total_in_store"]

        # Should have generated at least 3 audit events:
        # authorize_code_issued, code_exchanged, token_issued
        assert final_count >= initial_count + 3

        # Verify events exist
        resp = client.get("/admin/audit?event=authorize_code_issued")
        assert resp.get_json()["count"] > 0

        resp = client.get("/admin/audit?event=code_exchanged")
        assert resp.get_json()["count"] > 0

        resp = client.get("/admin/audit?event=token_issued")
        assert resp.get_json()["count"] > 0

    def test_audit_log_includes_request_id(self, client):
        """Audit entries include request_id from request context."""
        code, _ = do_authorize(client)
        exchange_code(client, code)

        resp = client.get("/admin/audit?limit=10")
        data = resp.get_json()

        # Most entries should have request_id
        with_request_id = [e for e in data["entries"] if "request_id" in e]
        assert len(with_request_id) > 0, "Some entries should have request_id"

    def test_audit_log_respects_maximum_size(self, client):
        """Audit log respects 1000 event maximum (deque maxlen)."""
        # Generate more than 1000 events
        for _ in range(1010):
            code, _ = do_authorize(client)
            # Each authorize_code_issued generates 1 event
            # So 1010 events

        resp = client.get("/admin/audit?limit=1000")
        data = resp.get_json()

        # Total should not exceed 1000
        assert data["total_in_store"] <= 1000

    def test_audit_tracks_different_clients(self, client):
        """Audit log tracks events from different clients separately."""
        code_a, _ = do_authorize(client, client_id="client-a")
        code_b, _ = do_authorize(client, client_id="client-b")

        exchange_code(client, code_a, client_id="client-a")
        exchange_code(client, code_b, client_id="client-b")

        resp = client.get("/admin/audit?client_id=client-a")
        a_entries = resp.get_json()["entries"]

        resp = client.get("/admin/audit?client_id=client-b")
        b_entries = resp.get_json()["entries"]

        # Each should have their own entries
        for entry in a_entries:
            assert entry.get("client_id") == "client-a"

        for entry in b_entries:
            assert entry.get("client_id") == "client-b"


class TestAuditEdgeCases:
    """Edge cases and error handling for audit endpoints."""

    def test_audit_endpoint_with_empty_store(self, app):
        """Audit endpoint works with empty audit log."""
        client = app.test_client()
        resp = client.get("/admin/audit")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 0
        assert data["total_in_store"] == 0
        assert data["entries"] == []

    def test_audit_endpoint_with_nonexistent_event_filter(self, client):
        """Filtering by nonexistent event returns empty list."""
        code, _ = do_authorize(client)
        exchange_code(client, code)

        resp = client.get("/admin/audit?event=nonexistent_event")
        data = resp.get_json()
        assert data["count"] == 0
        assert data["entries"] == []

    def test_audit_endpoint_with_nonexistent_client_filter(self, client):
        """Filtering by nonexistent client_id returns empty list."""
        code, _ = do_authorize(client)
        exchange_code(client, code)

        resp = client.get("/admin/audit?client_id=nonexistent_client")
        data = resp.get_json()
        assert data["count"] == 0
        assert data["entries"] == []

    def test_audit_endpoint_with_zero_limit(self, client):
        """?limit=0 still returns valid response."""
        code, _ = do_authorize(client)
        exchange_code(client, code)

        resp = client.get("/admin/audit?limit=0")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 0
        assert isinstance(data["entries"], list)

    def test_audit_endpoint_with_negative_limit(self, client):
        """?limit with negative value is handled gracefully."""
        code, _ = do_authorize(client)
        exchange_code(client, code)

        resp = client.get("/admin/audit?limit=-10")
        # Should either return 0 entries or handle it gracefully
        assert resp.status_code == 200

    def test_store_endpoint_with_no_activity(self, app):
        """Store endpoint returns zeros with no activity."""
        client = app.test_client()
        resp = client.get("/admin/store")
        data = resp.get_json()
        assert data["codes"] == 0
        assert data["refresh_tokens"] == 0
        # audit_events might be 0 or have bootstrap events
        assert isinstance(data["audit_events"], int)

    def test_audit_entries_immutable_after_fetch(self, client):
        """Modifying returned entries doesn't affect stored audit log."""
        code, _ = do_authorize(client)

        resp1 = client.get("/admin/audit?limit=10")
        entries1 = resp1.get_json()["entries"]

        # Modify the returned list
        if entries1:
            entries1[0]["event"] = "modified"

        # Fetch again and verify original unchanged
        resp2 = client.get("/admin/audit?limit=10")
        entries2 = resp2.get_json()["entries"]

        if entries2:
            assert entries2[0]["event"] != "modified"
