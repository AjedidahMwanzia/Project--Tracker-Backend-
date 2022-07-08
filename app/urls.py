
from django.urls import path
from . import  views
from django.contrib.auth import views as auth_views
from rest_framework.authtoken.views import obtain_auth_token


urlpatterns = [
    
    path('',views.home,name='home'),
    path('api/register/',views.register_user),
    path('api/login/',views.LoginView.as_view()),
    path('api/users/', views.users),
    path('api/user/', views.UserView.as_view()),
    path( 'api/logout/', views.LogoutView.as_view()),
    path('api/profile/', views.ProfileList.as_view()),
    path('api/users/', views.UserList.as_view()),
    path('api-token-auth/', obtain_auth_token),
    path('api/projects/',views.ProjectList.as_view()),
    path('api/cohort/', views.CohortList.as_view()),
  

]