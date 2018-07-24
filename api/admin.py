# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from __future__ import unicode_literals

from django.contrib import admin

# Register your models here.
from models import User, Images, UserImages

# Register your models here.
admin.site.register(User)
admin.site.register(Images)
admin.site.register(UserImages)
