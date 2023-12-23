from db.models.user import UserDB, User


def user_schema(user: UserDB):
    return {'id': str(user['_id']), 'username': user['username'], 'full_name': user['full_name'], 'hashed_password': user['hashed_password'], 'disabled': user['disabled']}

def users_schema(users: list[UserDB]) -> list:
    return [user_schema(user) for user in users]