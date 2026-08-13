import shlex
from datetime import datetime


Filter = tuple[str, str, str]


def parse_filter_expression(
    expression: str,
) -> list[Filter]:
    """
    Parse filter expressions.

    Examples:
        username=hosni
        username!=ansible
        exclude=ansible,oopser

    Returns:
        [
            ("username", "=", "hosni"),
            ("exclude", "=", "ansible,oopser"),
        ]
    """

    if not expression:
        return []

    operators = ["<=", ">=", "!=", "<", ">", "="]
    filters: list[Filter] = []

    for token in shlex.split(expression):

        for operator in operators:

            if operator not in token:
                continue

            field, value = token.split(operator, 1)

            field = field.strip()
            value = value.strip()

            if not field or not value:
                raise ValueError(
                    f"Invalid filter token: {token}"
                )

            filters.append(
                (field, operator, value)
            )

            break

        else:
            raise ValueError(
                f"Invalid filter token: {token}"
            )

    return filters


def get_users_excluded(
    filters: list[Filter],
) -> list[str]:
    """
    Return all users excluded by the filter expression.

    Example:
        exclude=ansible,oopser

    Returns:
        ["ansible", "oopser"]
    """

    users_excluded: set[str] = set()

    for field, operator, value in filters:

        if field != "exclude":
            continue

        if operator != "=":
            raise ValueError(
                "The 'exclude' filter only supports '='."
            )

        users_excluded.update(
            username.strip()
            for username in value.split(",")
            if username.strip()
        )

    return sorted(users_excluded)


def apply_filters(
    user,
    host,
    filters: list[Filter],
) -> bool:
    """Return True if the user matches all filters."""

    for field, operator, value in filters:

        # Excluded users
        if field == "exclude":

            users_excluded = {
                username.strip()
                for username in value.split(",")
                if username.strip()
            }

            if user.username in users_excluded:
                return False

            continue

        # Username
        if field == "username":
            current = user.username

        # Hostname
        elif field == "host":
            current = host.hostname

        # Unknown field
        else:
            raise ValueError(
                f"Unknown filter field: {field}"
            )

        # Comparison logic
        if operator == "=" and current != value:
            return False

        elif operator == "!=" and current == value:
            return False

    return True
