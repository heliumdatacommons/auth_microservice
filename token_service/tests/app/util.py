from token_service.models import User

def create_fake_user():
    """
    Create a test user.

    Return a User object.
    """
    user = User()
    user.sub = 1
    user.user_name = 'john'
    user.name = 'doe'

    user.save()

    return user
