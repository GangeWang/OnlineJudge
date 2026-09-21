"""Server-observed session context and atomic exam access policy.

Cookies and fingerprints are copyable risk signals, not hardware credentials.
The default exam policy reserves a source IP for one account for three hours.
"""
from contextlib import contextmanager
import os
import secrets

from database import get_connection, hash_session_token

def exam_mode():
    return os.getenv("EXAM_MODE", "true").lower() not in {"false", "0", "no"}

def registration_enabled():
    return not exam_mode() and os.getenv("REGISTRATION_ENABLED", "false").lower() in {"true", "1", "yes"}


@contextmanager
def security_transaction():
    # Shared by all API workers. Serializes identity checks and session issuance,
    # including different users attempting to claim the same source concurrently.
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK('oj_auth_policy', 10) AS acquired")
            if cursor.fetchone()["acquired"] != 1:
                raise RuntimeError("Authentication policy lock unavailable")
        try:
            connection.begin()
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            with connection.cursor() as cursor:
                cursor.execute("SELECT RELEASE_LOCK('oj_auth_policy')")

def _block(cursor, user_ids, reason, context, session_hash=None):
    for user_id in sorted(set(user_ids)):
        cursor.execute("UPDATE users SET blocked_until = CURRENT_TIMESTAMP() + INTERVAL 3 HOUR WHERE id = %s", (user_id,))
        cursor.execute("UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP() WHERE user_id = %s AND revoked_at IS NULL", (user_id,))
        cursor.execute("""
            INSERT INTO security_events
                (user_id, reason, ip_address, device_id, browser_fingerprint, session_hash)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, reason, context["ip_address"], context["device_id"], context["browser_fingerprint"], session_hash))


def _other_source_users(cursor, user_id, context):
    cursor.execute("""
        SELECT DISTINCT user_id FROM login_events
        WHERE user_id <> %s AND logged_in_at >= CURRENT_TIMESTAMP() - INTERVAL 3 HOUR
          AND (device_id = %s OR
               (ip_address = %s AND (browser_fingerprint = %s OR %s)))
    """, (user_id, context["device_id"], context["ip_address"], context["browser_fingerprint"], exam_mode()))
    return [row["user_id"] for row in cursor.fetchall()]


def issue_session(user_id, context, device_name=""):
    """Every credential-verified attempt is recorded, including denied logins."""
    with security_transaction() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT blocked_until > CURRENT_TIMESTAMP() AS blocked FROM users WHERE id = %s", (user_id,))
            blocked = cursor.fetchone()["blocked"]
            others = _other_source_users(cursor, user_id, context)
            cursor.execute("""
                SELECT id FROM login_events WHERE user_id = %s
                  AND logged_in_at >= CURRENT_TIMESTAMP() - INTERVAL 3 HOUR
                  AND (device_id <> %s OR ip_address <> %s OR browser_fingerprint <> %s)
                LIMIT 1
            """, (user_id, context["device_id"], context["ip_address"], context["browser_fingerprint"]))
            changed = cursor.fetchone() is not None
            reason = "account_conflict" if others else "context_conflict" if changed else "blocked" if blocked else "accepted"
            if context["ip_address"] == "unknown":
                reason = "unknown_source"
            cursor.execute("""
                INSERT INTO login_events (user_id, ip_address, device_id, browser_fingerprint, device_name, outcome)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, context["ip_address"], context["device_id"], context["browser_fingerprint"], device_name, reason))
            if others or changed:
                _block(cursor, [user_id, *others], reason, context)
            if reason != "accepted":
                return None
            token = secrets.token_urlsafe(32)
            cursor.execute("""
                INSERT INTO sessions (token_hash, user_id, device_id, browser_fingerprint, ip_address, expires_at)
                VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP() + INTERVAL 12 HOUR)
            """, (hash_session_token(token), user_id, context["device_id"], context["browser_fingerprint"], context["ip_address"]))
            return token

def check_session(connection, token, context):
    """Return (session, HTTP error); caller commits even when access is denied."""
    if not token:
        return None, 401
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT s.*, u.username, u.blocked_until > CURRENT_TIMESTAMP() AS blocked
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = %s AND s.expires_at > CURRENT_TIMESTAMP()
        """, (hash_session_token(token),))
        session = cursor.fetchone()
        if not session or not session["ip_address"]:
            # Legacy tokens have no binding; force a new login after upgrade.
            return None, 401
        if session["revoked_at"] or session["blocked"]:
            return session, 403
        if any(session[key] != context[key] for key in ("device_id", "ip_address", "browser_fingerprint")):
            others = _other_source_users(cursor, session["user_id"], context)
            _block(cursor, [session["user_id"], *others], "session_context_mismatch", context, session["token_hash"])
            return session, 403
        return session, None

def audit_submission(context, problem_id, token):
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO submission_audit
                    (session_hash, ip_address, device_id, browser_fingerprint, problem_id, outcome)
                VALUES (%s, %s, %s, %s, %s, 'received')
            """, (hash_session_token(token) if token else None, context["ip_address"], context["device_id"], context["browser_fingerprint"], problem_id[:32]))
            return cursor.lastrowid

def finish_audit(audit_id, outcome, user_id=None, submission_id=None):
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("UPDATE submission_audit SET outcome=%s, user_id=%s, submission_id=%s WHERE id=%s", (outcome, user_id, submission_id, audit_id))
