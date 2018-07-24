from django.contrib.auth import authenticate
from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers
from rest_framework.authtoken.models import Token

from models import User, Images, UserImages


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ("id", "username", "email", "password", "confirm_password")

    def create(self, validated_data):
        del validated_data["confirm_password"]
        return super(UserRegistrationSerializer, self).create(validated_data)

    def validate(self, attrs):
        if attrs.get('password') != attrs.get('confirm_password'):
            raise serializers.ValidationError("Those passwords don't match.")
        return attrs


class UserLoginSerializer(serializers.Serializer):
    email = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

    default_error_messages = {
        'inactive_account': _('User account is disabled.'),
        'invalid_credentials': _('Unable to login with provided credentials.')
    }

    def __init__(self, *args, **kwargs):
        super(UserLoginSerializer, self).__init__(*args, **kwargs)
        self.user = None

    def validate(self, attrs):
        self.user = authenticate(
            username=attrs.get("email"),
            password=attrs.get('password'))
        if self.user:
            if not self.user.is_active:
                raise serializers.ValidationError(
                    self.error_messages['inactive_account'])
            return attrs
        else:
            raise serializers.ValidationError(
                self.error_messages['invalid_credentials'])


# serialize data of user for common need of user table.
class UserProfileSerializer(serializers.ModelSerializer):
    contact_no = serializers.IntegerField(required=False)

    class Meta:
        model = User
        fields = (
            'email', 'id', 'username',
            'created', 'country_code', 'contact_no', 'city',
            'state', 'country', 'is_password_changed', 'is_superuser')


# serialize data of courses.
class UserImagesSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserImages
        fields = '__all__'


class TokenSerializer(serializers.ModelSerializer):
    auth_token = serializers.CharField(source='key')

    class Meta:
        model = Token
        fields = ("auth_token",)


class ImageListSerializer(serializers.Serializer):
    image = serializers.ListField(
        child=serializers.FileField(max_length=100000,
                                    allow_empty_file=False,
                                    use_url=False))

    def create(self, validated_data):
        image = validated_data.pop('image')
        for img in image:
            photo = Images.objects.create(image=img, **validated_data)
        return photo


class ImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Images
        fields = '__all__'


class ImageUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Images
        fields = ('name', 'description', 'up_vote', 'is_approved', 'created', 'modified')
