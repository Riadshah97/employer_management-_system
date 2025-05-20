from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.translation import gettext_lazy as _
import logging

logger = logging.getLogger(__name__)

class IdentityService:
    def login(self, email, password, request=None):
        """
        Authenticate a user and generate tokens
        """
        try:
            user = authenticate(username=email, password=password)
            
            if not user:
                return None, None, _("Invalid credentials. Please check your email and password.")
                
            if not user.is_active:
                return None, None, _("Your account is inactive. Please contact support.")
                
            refresh = RefreshToken.for_user(user)
            tokens = {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
            
            return user, tokens, None
            
        except Exception as e:
            logger.error({"event": "IdentityService:login", "message": "Login error", "error": str(e)})
            return None, None, _("An unexpected error occurred. Please try again later.")

def log_activity(user, action, description, request=None):
    """
    Log user activity
    """
    try:
        # Here you would typically save to a database or log to a file
        ip = request.META.get('REMOTE_ADDR') if request else None
        logger.info({
            "event": f"UserActivity:{action}",
            "user_id": user.id,
            "user_email": user.email,
            "description": description,
            "ip": ip
        })
    except Exception as e:
        logger.error({"event": "log_activity", "message": "Failed to log activity", "error": str(e)})