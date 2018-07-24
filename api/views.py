# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import re

# Create your views here.
from rest_framework import status, schemas, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes, renderer_classes
from rest_framework.generics import CreateAPIView, GenericAPIView
from rest_framework.parsers import MultiPartParser, JSONParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_swagger.renderers import OpenAPIRenderer, SwaggerUIRenderer

from api import validations_utils, utils, messages
from api.models import Images
from api.permissions import UserPermissions, IsAuthenticated
from api.serializers import (UserRegistrationSerializer,
                             UserLoginSerializer,
                             TokenSerializer,
                             ImageListSerializer, ImageSerializer)

from rest_framework.parsers import MultiPartParser
from rest_framework.decorators import parser_classes
from api.validations_utils import ValidationException


@api_view()
@permission_classes((AllowAny,))
@renderer_classes([OpenAPIRenderer, SwaggerUIRenderer])
def schema_view(request):
    generator = schemas.SchemaGenerator(title='Rest Swagger')
    return Response(generator.get_schema(request=request))


class UserRegistrationAPIView(CreateAPIView):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = UserRegistrationSerializer

    def create(self, request, *args, **kwargs):
        data = validations_utils.email_validation(
            request.data)  # Validates email id, it returns lower-cased email in data.
        data = validations_utils.password_validation(data)  # Validates password criteria.
        data['password'] = data['confirm_password'] = utils.hash_password(data['password'])
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        user = serializer.instance
        token, created = Token.objects.get_or_create(user=user)
        data = serializer.data
        data["token"] = token.key
        headers = self.get_success_headers(serializer.data)
        return Response(data, status=status.HTTP_201_CREATED, headers=headers)


class UserLoginAPIView(GenericAPIView):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = UserLoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.user
            try:
                login_user = utils.authenticate_user(
                    user, request.data)  # Authorizes the user and returns appropriate data.
            except ValidationException as e:  # Generic exception
                return Response(e.errors, status=e.status)
            return Response(login_user, status=status.HTTP_200_OK)
        else:
            return Response(
                data=serializer.errors,
                status=status.HTTP_400_BAD_REQUEST,
            )


class UserLogoutAPIView(APIView):
    permission_classes = [UserPermissions, IsAuthenticated]

    def post(self, request, *args, **kwargs):
        Token.objects.filter(user=request.user).delete()
        return Response(status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    permission_classes = [UserPermissions, IsAuthenticated]

    def put(self, request):
        """
        ### Change Password
        * While changing password for user registered with email, PUT request
        requires two fields and their values:
            * current_password - String
            * new_password - String
        * Possible HTTP status codes and JSON response:
            * `HTTP_200_OK` - If password change was successful:
                    {
                     "user_id": integer,
                     "message": "Password updated successfully"
                    }
            * `HTTP_401_UNAUTHORIZED` - If user provided incorrect value for
            current_password:
                    {
                     "message": "Current password is incorrect."
                    }
            * `HTTP_400_BAD_REQUEST` - If new_password is same as current_password:
                    {
                     "message": "New password cannot be same as current password"
                    }
            * `HTTP_500_INTERNAL_SERVER_ERROR` - Internal server error
            :param pk:
            :param request:
        """
        try:
            request.data['current_password']
        except KeyError:
            return Response(messages.REQUIRED_CURRENT_PASSWORD,
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            new_password = request.data['new_password']
            if new_password is None or not re.match(
                    r'[A-Za-z0-9@#$%^&+=]+', new_password):
                return Response(messages.PASSWORD_NECESSITY,
                                status=status.HTTP_406_NOT_ACCEPTABLE)
            else:
                pass
        except KeyError:
            return Response(
                messages.REQUIRED_NEW_PASSWORD,
                status=status.HTTP_400_BAD_REQUEST)
        data_keys = request.data.keys()
        # Change Password will only require current_password and new_password.
        if 'current_password' in data_keys and 'new_password' in data_keys:
            current_password = request.data['current_password']
            new_password = request.data['new_password']
            try:
                password = utils.change_password(
                    current_password, new_password, request.user)  # Changes password.
                return Response(password, status=status.HTTP_200_OK)
            except ValidationException as e:
                return Response(e.errors, status=e.status)


@parser_classes((MultiPartParser, JSONParser,))
class ImageView(APIView):
    """
    List all snippets, or create a new snippet.
    """
    permission_classes = [UserPermissions, IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """
            **Create Image**

            Login an existing user.

            Used for creating images in gallery.

            > POST

            * Requires following fields of users in JSON format:

                1. `images` - List

            * Returns image data on successful saving of.
            :param request:
            """
        data = request.data
        try:
            response = utils.create_image(data)  # Creates user with request data.
            return Response(response, status=status.HTTP_201_CREATED)
        except ValidationException as e:  # Generic exception
            return Response(e.errors, status=e.status)

    def get(self, request, *args, **kwargs):
        if request.user.is_superuser:
            images = Images.objects.all()
        else:
            images = Images.objects.filter(is_approved=True)
        serializer = ImageSerializer(images, many=True)
        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        data = request.data
        try:
            image = Images.objects.get(id=data['id'])
        except Images.DoesNotExist:
            raise ValidationException(
                messages.IMAGE_DOES_NOT_EXISTS,
                status.HTTP_404_NOT_FOUND)
        try:
            updated_data = utils.update_image(data, image)  # Updates image data.
            return Response(updated_data, status=status.HTTP_200_OK)
        except ValidationException as e:  # Generic exception
            return Response(e.errors, status=e.status)