"""Grant or revoke the administrator role.

    docker compose run --rm api python scripts/grant_admin.py --list
    docker compose run --rm api python scripts/grant_admin.py <user-id>
    docker compose run --rm api python scripts/grant_admin.py <user-id> --revoke

A script rather than a psql one-liner because the grant is itself an
administrative change and has to reach the audit trail. Doing it by hand in
SQL leaves no record of who gained access or when.

The user must sign in once first -- the profile row is created on their
first authenticated request, and there is nothing to promote before that.
"""

import argparse
import sys
import uuid
from pathlib import Path

# Python puts the script's own directory on sys.path, not the app root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from app.db import AuditEvent, Profile, SessionLocal  # noqa: E402

# Recorded as the actor when the grant comes from the command line rather
# than from a signed-in administrator.
CONSOLE_ACTOR = uuid.UUID(int=0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("user_id", nargs="?", help="Supabase user id (uuid)")
    parser.add_argument("--revoke", action="store_true", help="demote to user")
    parser.add_argument("--list", action="store_true", help="show every profile and role")
    args = parser.parse_args()

    with SessionLocal() as session:
        if args.list:
            rows = session.scalars(select(Profile).order_by(Profile.created_at)).all()
            if not rows:
                print("no profiles yet -- sign in once to create one")
                return 0
            for row in rows:
                print(f"{row.id}  {row.role:<6}  {row.created_at:%Y-%m-%d %H:%M}")
            return 0

        if not args.user_id:
            parser.error("user_id is required unless --list is given")

        try:
            user_id = uuid.UUID(args.user_id)
        except ValueError:
            print(f"not a uuid: {args.user_id}", file=sys.stderr)
            return 1

        profile = session.get(Profile, user_id)
        if profile is None:
            print(
                f"no profile for {user_id}.\n"
                "They must sign in once before the role can be changed.",
                file=sys.stderr,
            )
            return 1

        previous = profile.role
        profile.role = "user" if args.revoke else "admin"
        if previous == profile.role:
            print(f"{user_id} is already {previous}; nothing to do")
            return 0

        session.add(
            AuditEvent(
                actor=CONSOLE_ACTOR,
                action="role.change",
                target=str(user_id),
                meta=f"{previous} -> {profile.role} (console)",
            )
        )
        session.commit()
        print(f"{user_id}: {previous} -> {profile.role}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
