from django.urls import path
from . import views
app_name = 'apps'
urlpatterns = [

    path('api/signup/', views.signup_view, name='signup_view'),
    path('api/signin/', views.signin_view, name='signin_view'),
    path('api/logout/', views.logout_view, name='logout'),
]