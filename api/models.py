from __future__ import unicode_literals

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _


# Create your models here.


class CustomUserManager(BaseUserManager):
    def _create_user(self, email, password, is_staff,
                     is_superuser, **extra_fields):
        """
        Creates and saves a User with the given email and password.
        """
        now = timezone.now()
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, is_staff=is_staff,
                          is_active=True,
                          is_superuser=is_superuser, last_login=now,
                          date_joined=now, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        return self._create_user(email, password, False, False,
                                 **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        return self._create_user(email, password, True, True,
                                 **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """this class represents the user Model.
    """

    class Meta:
        db_table = 'users'
        managed = True

    username = models.CharField(max_length=100, blank=True, null=True)
    email = models.EmailField(max_length=254, unique=True)
    country_code = models.IntegerField(blank=True, null=True)
    contact_no = models.BigIntegerField(blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)
    is_password_changed = models.BooleanField(default=False)
    city = models.CharField(max_length=100, blank=True, null=True)
    state = models.CharField(max_length=100, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    is_staff = models.BooleanField(_('staff status'), default=False,
                                   help_text=_('Designates whether the user can log into this admin '
                                               'site.'))
    is_active = models.BooleanField(_('active'), default=True,
                                    help_text=_('Designates whether this user should be treated as '
                                                'active. Unselected this instead of deleting accounts.'))
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s' % self.username
        return full_name.strip()

    def get_short_name(self):
        """Returns the short name for the user."""
        return self.username

    def __unicode__(self):
        return self.email


class UserResetPassword(models.Model):
    class Meta:
        db_table = 'user_reset_password'

    user = models.OneToOneField(User)
    is_valid_key = models.BooleanField(default=False)
    key = models.CharField(max_length=40, blank=True)
    key_expires = models.DateTimeField()

    def __unicode__(self):
        return self.user

    def __repr__(self):
        return str(self.id)


class Images(models.Model):

    class Meta:
        db_table = 'images'

    name = models.CharField(max_length=100, blank=True)
    description = models.TextField(max_length=4000, blank=True)
    image = models.ImageField(blank=False)
    up_vote = models.IntegerField(default=0)
    is_approved = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    def __unicode__(self):
        return self.name

    def __repr__(self):
        return str(self.name)


class UserImages(models.Model):
    class Meta:
        db_table = 'user_images'
        managed = True

    user = models.ForeignKey(User)
    image = models.ForeignKey(Images)

    def __unicode__(self):
        return "%s - %s" % (self.user, self.image)

    def __repr__(self):
        return "%s - %s" % (self.user, self.image)
