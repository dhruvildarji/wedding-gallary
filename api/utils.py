from django.contrib.auth.hashers import make_password
import messages
from serializers import *
from validations_utils import ValidationException
from rest_framework import status


def generate_token(user):
    # Token table is of Django Rest Framework
    # Creates the token at registration time
    token = Token.objects.create(user=user)
    # Return only the key with is associated with the object
    return token.key


def fetch_token(user):
    try:
        # Get the goal for the specified user and return key
        token = Token.objects.get(user_id=user.id)
        return token.key
    except Token.DoesNotExist:
        raise ValidationException(messages.TOKEN_NOT_FOUND, status.HTTP_404_NOT_FOUND)


def hash_password(password):
    return make_password(password)


def create_user(data):
    user_serializer = UserRegistrationSerializer(data=data)
    if user_serializer.is_valid():
        user = user_serializer.save()
        token = Token.objects.create(user=user)
        keys = ['id', 'first_name', 'last_name', 'email', 'contact_no', 'created'
                ]  # data that we want to return as JSON response
        user_response = {k: v for k, v in user_serializer.data.iteritems() if k in keys}
        user_response['token'] = token.key
        return user_response
    else:
        raise ValidationException(
            user_serializer.errors, status.HTTP_400_BAD_REQUEST)


def create_image(data):
    image_serializer = ImageSerializer(data=data)
    if image_serializer.is_valid():
        image_serializer.save()
        return image_serializer.data
    else:
        raise ValidationException(
            image_serializer.errors, status.HTTP_400_BAD_REQUEST)


def update_user(data, user):
    user_serializer = UserProfileSerializer(data=data, instance=user)
    if user_serializer.is_valid():
        user_serializer.save()
        return user_serializer.data
    else:
        raise ValidationException(user_serializer.errors,
                                  status.HTTP_400_BAD_REQUEST)


def authenticate_user(user, data):
    if user:
        token, _ = Token.objects.get_or_create(user=user)
        user_serializer = UserProfileSerializer(user, data=data)
        if user_serializer.is_valid():
            user_serializer_dict = user_serializer.data
            user_serializer_dict.update(TokenSerializer(token).data)
            user_serializer_dict.update(messages.LOGIN_SUCCESSFUL)
            return user_serializer_dict
        else:
            raise ValidationException(
                user_serializer.errors,
                status.HTTP_400_BAD_REQUEST)
    else:
        raise ValidationException(
            messages.INVALID_EMAIL_OR_PASSWORD,
            status.HTTP_401_UNAUTHORIZED)


def change_password(current_password, new_password, user):
    if user.check_password(current_password):

        if current_password != new_password:
            user.set_password(new_password)
            user.is_password_changed = True
            user.save()
            resp = {'user_id': user.id}
            resp.update(messages.PASSWORD_CHANGED)
            return resp
        else:
            raise ValidationException(messages.SAME_PASSWORD,
                                      status.HTTP_406_NOT_ACCEPTABLE)
    else:
        raise ValidationException(messages.CURRENT_PASSWORD_INCORRECT,
                                  status.HTTP_401_UNAUTHORIZED)


def update_image(data, image):
    image_serializer = ImageUpdateSerializer(data=data, instance=image)
    if image_serializer.is_valid():
        image_serializer.save()
        return image_serializer.data
    else:
        raise ValidationException(image_serializer.errors,
                                  status.HTTP_400_BAD_REQUEST)
