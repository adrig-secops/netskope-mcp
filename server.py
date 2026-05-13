import itertools
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastmcp import FastMCP
from netskope import NetskopeClient

load_dotenv(Path(__file__).parent / ".env")

mcp = FastMCP(
    name="Netskope MCP",
    instructions=(
        "Provides full read-write access to the Netskope REST API v2 via the official Python SDK. "
        "Covers alerts, events, incidents, URL lists, publishers, private apps, SCIM users/groups, "
        "and steering/infrastructure."
    ),
)


def _client() -> NetskopeClient:
    tenant = os.environ["NETSKOPE_TENANT"]
    token = os.environ["NETSKOPE_API_TOKEN"]
    return NetskopeClient(tenant=tenant, api_token=token)


def _dump(obj: Any) -> Any:
    """Convert Pydantic models and paginated responses to plain dicts/lists."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "__iter__") and not isinstance(obj, (str, bytes, dict)):
        return [_dump(item) for item in obj]
    return obj


def _page(paginator: Any, n: int) -> list:
    """Consume at most n items from a paginator and dump them."""
    return _dump(itertools.islice(paginator, n))


# ---------------------------------------------------------------------------
# ALERTS
# ---------------------------------------------------------------------------


@mcp.tool()
def list_alerts(
    query: str | None = None,
    fields: list[str] | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    group_by: str | None = None,
    order_by: str | None = None,
    descending: bool = True,
    page_size: int = 100,
) -> list[dict]:
    """List security alerts with optional JQL filtering and time ranges.

    Args:
        query: JQL filter expression (e.g. 'severity:HIGH').
        fields: Specific fields to return.
        start_time: ISO-8601 start timestamp.
        end_time: ISO-8601 end timestamp.
        group_by: Field to group results by.
        order_by: Field to sort results by.
        descending: Sort order (default True).
        page_size: Number of results per page (default 100).
    """
    with _client() as c:
        results = c.alerts.list(
            query=query,
            fields=fields,
            start_time=start_time,
            end_time=end_time,
            group_by=group_by,
            order_by=order_by,
            descending=descending,
            page_size=page_size,
        )
        return _page(results, page_size)


@mcp.tool()
def get_alert(alert_id: str) -> dict:
    """Retrieve a specific alert by its ID.

    Args:
        alert_id: The alert ID to retrieve.
    """
    with _client() as c:
        return _dump(c.alerts.get(alert_id))


# ---------------------------------------------------------------------------
# EVENTS
# ---------------------------------------------------------------------------


@mcp.tool()
def list_events(
    event_type: str,
    query: str | None = None,
    fields: list[str] | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    group_by: str | None = None,
    order_by: str | None = None,
    descending: bool = True,
    page_size: int = 100,
) -> list[dict]:
    """List security events for a given event type.

    Args:
        event_type: One of 'network', 'application', 'page', 'audit', 'infrastructure'.
        query: JQL filter expression.
        fields: Specific fields to return.
        start_time: ISO-8601 start timestamp.
        end_time: ISO-8601 end timestamp.
        group_by: Field to group results by.
        order_by: Field to sort results by.
        descending: Sort order (default True).
        page_size: Number of results per page (default 100).
    """
    with _client() as c:
        results = c.events.list(
            event_type,
            query=query,
            fields=fields,
            start_time=start_time,
            end_time=end_time,
            group_by=group_by,
            order_by=order_by,
            descending=descending,
            page_size=page_size,
        )
        return _page(results, page_size)


# ---------------------------------------------------------------------------
# INCIDENTS
# ---------------------------------------------------------------------------


@mcp.tool()
def list_incidents(
    query: str | None = None,
    fields: list[str] | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    page_size: int = 100,
) -> list[dict]:
    """List security incidents with optional filtering.

    Args:
        query: JQL filter expression.
        fields: Specific fields to return.
        start_time: ISO-8601 start timestamp.
        end_time: ISO-8601 end timestamp.
        page_size: Number of results per page (default 100).
    """
    with _client() as c:
        results = c.incidents.list(
            query=query,
            fields=fields,
            start_time=start_time,
            end_time=end_time,
            page_size=page_size,
        )
        return _page(results, page_size)


@mcp.tool()
def update_incident(
    incident_id: str,
    field: str,
    old_value: Any,
    new_value: Any,
    user: str,
) -> dict:
    """Update a field on a specific incident.

    Args:
        incident_id: The incident ID to update.
        field: The field name to change.
        old_value: The current value of the field.
        new_value: The new value to set.
        user: The user performing the update.
    """
    with _client() as c:
        return c.incidents.update(incident_id, field=field, old_value=old_value, new_value=new_value, user=user)


@mcp.tool()
def get_incident_forensics(dlp_incident_id: str) -> dict:
    """Retrieve DLP forensics data for an incident.

    Args:
        dlp_incident_id: The DLP incident ID.
    """
    with _client() as c:
        return c.incidents.get_forensics(dlp_incident_id)


@mcp.tool()
def get_user_confidence_index(username: str) -> dict:
    """Get the User Confidence Index (UCI / risk score) for a user.

    Args:
        username: The username to query.
    """
    with _client() as c:
        return _dump(c.incidents.get_uci(username))


@mcp.tool()
def get_anomalies(
    users: list[str] | None = None,
    timeframe: str | None = None,
    severity: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    """Retrieve UBA (User Behavior Analytics) anomalies.

    Args:
        users: Filter anomalies to specific usernames.
        timeframe: Time window to query (e.g. '7d', '24h').
        severity: Filter by severity level.
        limit: Maximum number of anomalies to return.
    """
    with _client() as c:
        results = c.incidents.get_anomalies(
            users=users,
            timeframe=timeframe,
            severity=severity,
            limit=limit,
        )
        return _dump(results)


# ---------------------------------------------------------------------------
# URL LISTS
# ---------------------------------------------------------------------------


@mcp.tool()
def list_url_lists(page_size: int = 100) -> list[dict]:
    """List all URL lists (blocklists and allowlists).

    Args:
        page_size: Number of results per page (default 100).
    """
    with _client() as c:
        return _page(c.url_lists.list(page_size=page_size), page_size)


@mcp.tool()
def get_url_list(list_id: int) -> dict:
    """Retrieve a specific URL list by ID.

    Args:
        list_id: The URL list ID.
    """
    with _client() as c:
        return _dump(c.url_lists.get(list_id))


@mcp.tool()
def create_url_list(
    name: str,
    urls: list[str],
    list_type: str = "exact",
) -> dict:
    """Create a new URL list.

    Args:
        name: Name of the URL list.
        urls: List of URLs to include.
        list_type: Match type — 'exact' or 'regex' (default 'exact').
    """
    with _client() as c:
        return _dump(c.url_lists.create(name, urls, list_type=list_type))


@mcp.tool()
def update_url_list(
    list_id: int,
    name: str | None = None,
    urls: list[str] | None = None,
    list_type: str | None = None,
) -> dict:
    """Update an existing URL list.

    Args:
        list_id: The URL list ID to update.
        name: New name (optional).
        urls: New URL entries (optional).
        list_type: New match type — 'exact' or 'regex' (optional).
    """
    with _client() as c:
        return _dump(c.url_lists.update(list_id, name=name, urls=urls, list_type=list_type))


@mcp.tool()
def delete_url_list(list_id: int) -> dict:
    """Delete a URL list by ID.

    Args:
        list_id: The URL list ID to delete.
    """
    with _client() as c:
        return c.url_lists.delete(list_id)


@mcp.tool()
def deploy_url_lists() -> dict:
    """Deploy all pending URL list changes to the Netskope platform."""
    with _client() as c:
        return c.url_lists.deploy()


# ---------------------------------------------------------------------------
# PUBLISHERS
# ---------------------------------------------------------------------------


@mcp.tool()
def list_publishers(page_size: int = 100) -> list[dict]:
    """List all Netskope publisher instances.

    Args:
        page_size: Number of results per page (default 100).
    """
    with _client() as c:
        return _page(c.publishers.list(page_size=page_size), page_size)


@mcp.tool()
def get_publisher(publisher_id: int) -> dict:
    """Retrieve a specific publisher by ID.

    Args:
        publisher_id: The publisher ID.
    """
    with _client() as c:
        return _dump(c.publishers.get(publisher_id))


@mcp.tool()
def create_publisher(name: str, extra_fields: dict | None = None) -> dict:
    """Create a new publisher.

    Args:
        name: Publisher display name.
        extra_fields: Additional configuration fields (optional).
    """
    with _client() as c:
        return _dump(c.publishers.create(name, extra_fields=extra_fields))


@mcp.tool()
def update_publisher(
    publisher_id: int,
    name: str | None = None,
    extra_fields: dict | None = None,
) -> dict:
    """Update an existing publisher.

    Args:
        publisher_id: The publisher ID to update.
        name: New name (optional).
        extra_fields: Additional fields to update (optional).
    """
    with _client() as c:
        return _dump(c.publishers.update(publisher_id, name=name, extra_fields=extra_fields))


@mcp.tool()
def delete_publisher(publisher_id: int) -> dict:
    """Delete a publisher by ID.

    Args:
        publisher_id: The publisher ID to delete.
    """
    with _client() as c:
        return c.publishers.delete(publisher_id)


# ---------------------------------------------------------------------------
# PRIVATE APPS (ZTNA / NPA)
# ---------------------------------------------------------------------------


@mcp.tool()
def list_private_apps(
    filter_expr: str | None = None,
    fields: list[str] | None = None,
    page_size: int = 100,
) -> list[dict]:
    """List all ZTNA private applications.

    Args:
        filter_expr: Filter expression to narrow results (optional).
        fields: Specific fields to return (optional).
        page_size: Number of results per page (default 100).
    """
    with _client() as c:
        return _page(c.private_apps.list(filter_expr=filter_expr, fields=fields, page_size=page_size), page_size)


@mcp.tool()
def get_private_app(app_id: int) -> dict:
    """Retrieve a specific private app by ID.

    Args:
        app_id: The private app ID.
    """
    with _client() as c:
        return _dump(c.private_apps.get(app_id))


@mcp.tool()
def create_private_app(
    name: str,
    host: str,
    port: str,
    protocols: list[str] | None = None,
    publisher_ids: list[int] | None = None,
    extra_fields: dict | None = None,
) -> dict:
    """Create a new ZTNA private application.

    Args:
        name: Application display name.
        host: Hostname or IP of the private application.
        port: Port or port range (e.g. '443' or '8080-8090').
        protocols: List of protocols (e.g. ['TCP', 'UDP']).
        publisher_ids: List of publisher IDs to associate.
        extra_fields: Additional configuration fields (optional).
    """
    with _client() as c:
        return _dump(
            c.private_apps.create(
                name,
                host,
                port,
                protocols=protocols,
                publisher_ids=publisher_ids,
                extra_fields=extra_fields,
            )
        )


@mcp.tool()
def update_private_app(app_id: int, extra_fields: dict | None = None) -> dict:
    """Update a private application.

    Args:
        app_id: The private app ID to update.
        extra_fields: Fields to update (optional).
    """
    with _client() as c:
        return _dump(c.private_apps.update(app_id, extra_fields=extra_fields))


@mcp.tool()
def delete_private_app(app_id: int) -> dict:
    """Delete a private application by ID.

    Args:
        app_id: The private app ID to delete.
    """
    with _client() as c:
        return c.private_apps.delete(app_id)


# ---------------------------------------------------------------------------
# SCIM USERS
# ---------------------------------------------------------------------------


@mcp.tool()
def list_scim_users(filter_expr: str | None = None, page_size: int = 100) -> list[dict]:
    """List SCIM-provisioned users.

    Args:
        filter_expr: SCIM filter expression (e.g. 'userName eq "alice"').
        page_size: Number of results per page (default 100).
    """
    with _client() as c:
        return _page(c.scim.users.list(filter_expr=filter_expr, page_size=page_size), page_size)


@mcp.tool()
def get_scim_user(user_id: str) -> dict:
    """Retrieve a specific SCIM user by ID.

    Args:
        user_id: The SCIM user ID.
    """
    with _client() as c:
        return _dump(c.scim.users.get(user_id))


@mcp.tool()
def create_scim_user(
    user_name: str,
    email: str,
    active: bool,
    display_name: str,
    given_name: str,
    family_name: str,
) -> dict:
    """Provision a new SCIM user.

    Args:
        user_name: Username (typically email).
        email: User's email address.
        active: Whether the user account is active.
        display_name: Full display name.
        given_name: First name.
        family_name: Last name.
    """
    with _client() as c:
        return _dump(
            c.scim.users.create(
                user_name=user_name,
                email=email,
                active=active,
                display_name=display_name,
                given_name=given_name,
                family_name=family_name,
            )
        )


@mcp.tool()
def update_scim_user(user_id: str, fields: dict) -> dict:
    """Partially update a SCIM user (PATCH).

    Args:
        user_id: The SCIM user ID to update.
        fields: Dictionary of fields to update.
    """
    with _client() as c:
        return _dump(c.scim.users.update(user_id, fields))


@mcp.tool()
def delete_scim_user(user_id: str) -> dict:
    """Remove a SCIM user.

    Args:
        user_id: The SCIM user ID to delete.
    """
    with _client() as c:
        return c.scim.users.delete(user_id)


# ---------------------------------------------------------------------------
# SCIM GROUPS
# ---------------------------------------------------------------------------


@mcp.tool()
def list_scim_groups(filter_expr: str | None = None, page_size: int = 100) -> list[dict]:
    """List SCIM-provisioned groups.

    Args:
        filter_expr: SCIM filter expression (e.g. 'displayName eq "Engineering"').
        page_size: Number of results per page (default 100).
    """
    with _client() as c:
        return _page(c.scim.groups.list(filter_expr=filter_expr, page_size=page_size), page_size)


@mcp.tool()
def get_scim_group(group_id: str) -> dict:
    """Retrieve a specific SCIM group by ID.

    Args:
        group_id: The SCIM group ID.
    """
    with _client() as c:
        return _dump(c.scim.groups.get(group_id))


@mcp.tool()
def create_scim_group(display_name: str, member_ids: list[str]) -> dict:
    """Create a new SCIM group.

    Args:
        display_name: Group display name.
        member_ids: List of SCIM user IDs to add as members.
    """
    with _client() as c:
        return _dump(c.scim.groups.create(display_name=display_name, member_ids=member_ids))


@mcp.tool()
def update_scim_group(group_id: str, display_name: str, member_ids: list[str]) -> dict:
    """Replace a SCIM group (full PUT — replaces all members).

    Args:
        group_id: The SCIM group ID to update.
        display_name: New display name.
        member_ids: Complete list of SCIM user IDs (replaces existing members).
    """
    with _client() as c:
        return _dump(c.scim.groups.update(group_id, display_name=display_name, member_ids=member_ids))


@mcp.tool()
def delete_scim_group(group_id: str) -> dict:
    """Remove a SCIM group.

    Args:
        group_id: The SCIM group ID to delete.
    """
    with _client() as c:
        return c.scim.groups.delete(group_id)


# ---------------------------------------------------------------------------
# STEERING & INFRASTRUCTURE
# ---------------------------------------------------------------------------


@mcp.tool()
def get_steering_config(scope: str = "npa") -> dict:
    """Retrieve steering configuration for a given scope.

    Args:
        scope: One of 'npa', 'nsc', 'ztna', 'publishers' (default 'npa').
    """
    with _client() as c:
        return c.steering.get_config(scope=scope)


@mcp.tool()
def update_steering_config(scope: str, settings: dict) -> dict:
    """Update steering configuration (PATCH) for a given scope.

    Args:
        scope: One of 'npa', 'nsc', 'ztna', 'publishers'.
        settings: Dictionary of settings to apply.
    """
    with _client() as c:
        return c.steering.update_config(scope=scope, settings=settings)


@mcp.tool()
def list_pops(page_size: int = 100) -> list[dict]:
    """List all Netskope Points of Presence (PoPs).

    Args:
        page_size: Number of results per page (default 100).
    """
    with _client() as c:
        return _page(c.steering.list_pops(page_size=page_size), page_size)


@mcp.tool()
def list_tunnels(page_size: int = 100) -> list[dict]:
    """List all IPSec tunnels.

    Args:
        page_size: Number of results per page (default 100).
    """
    with _client() as c:
        return _page(c.steering.list_tunnels(page_size=page_size), page_size)


@mcp.tool()
def get_tunnel(tunnel_id: int) -> dict:
    """Retrieve a specific IPSec tunnel by ID.

    Args:
        tunnel_id: The tunnel ID.
    """
    with _client() as c:
        return _dump(c.steering.get_tunnel(tunnel_id))


if __name__ == "__main__":
    mcp.run()
