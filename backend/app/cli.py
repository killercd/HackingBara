import argparse
import getpass

from sqlalchemy import select

from .db import SessionLocal
from .models import User
from .security import hasher


def main():
    parser = argparse.ArgumentParser(description="HackingBara account management")
    parser.add_argument("command", choices=["create-user"])
    parser.add_argument("username")
    args = parser.parse_args()
    password = getpass.getpass("Password (minimum 12 characters): ")
    if len(password) < 12 or password != getpass.getpass("Confirm password: "):
        parser.error("Passwords must match and contain at least 12 characters")
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == args.username)):
            parser.error("Username already exists")
        db.add(User(username=args.username, password_hash=hasher.hash(password)))
        db.commit()
    print("Account created")


if __name__ == "__main__":
    main()
