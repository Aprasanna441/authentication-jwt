from django.urls import path
from myapp import views
from myapp.views import UserRegistrationView,UserLoginView,UserProfileView,ChangePasswordView,SendPasswordResetEmailView,UserPasswordResetView
urlpatterns = [    
      path('register/',UserRegistrationView.as_view(),name="registeruser" ),
      path('login/',UserLoginView.as_view(),name="login"),
      path('profile/',UserProfileView.as_view(),name="profile"),
      path('changepassword',ChangePasswordView.as_view(),name="changepassword"),
      path('send-reset-password-email/',SendPasswordResetEmailView.as_view(),name='send-reset-password-email'),
      path('reset-password/<uid>/<token>/',UserPasswordResetView.as_view(),name='reset-password')
      

    
]