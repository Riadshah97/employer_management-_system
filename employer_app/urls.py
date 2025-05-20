from django.urls import path
from .views import SignUpView, LoginView, UserProfileView, EmployerView

urlpatterns = [
    # Authentication endpoints
    path('auth/signup/', SignUpView.as_view(), name='signup'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/profile/', UserProfileView.as_view(), name='user-profile'),
    
    # Employer endpoints
    path('employers/', EmployerView.as_view(), name='employer-list'),
    path('employers/<int:pk>/', EmployerView.as_view(), name='employer-detail'),
]
