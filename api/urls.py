from django.conf.urls import url, include
from rest_framework.routers import DefaultRouter

from views import *

# router = DefaultRouter()
# router.register(r'^/$', ImageViewSet)

urlpatterns = [
    url(r'^register/$', UserRegistrationAPIView.as_view(), name="register"),
    url(r'^login/$', UserLoginAPIView.as_view(), name="login"),
    url(r'^logout/$', UserLogoutAPIView.as_view(), name="logout"),
    url(r'^change_password/$', ChangePasswordView.as_view(), name="change_password"),
    url(r'^images/$', ImageView.as_view(), name="update image"),
]
