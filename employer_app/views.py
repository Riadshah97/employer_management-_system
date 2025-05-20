from rest_framework import viewsets, generics, permissions, status
from rest_framework.response import Response
from django.utils.translation import gettext_lazy as _
import logging

from .models import User, Employer
from .serializers import UserSerializer, SignUpSerializer, LoginSerializer, EmployerSerializer
from .permissions import IsOwner
from .views_base import ApiView
from .services import IdentityService, log_activity

logger = logging.getLogger(__name__)

class SignUpView(ApiView):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.identity_service = IdentityService()

    def post(self, request):
        try:
            serializer = SignUpSerializer(data=request.data)
            if not serializer.is_valid():
                result = {
                    "message": _("Invalid input. Please check the provided details."),
                    "errors": serializer.errors,
                }
                return Response(result, status=status.HTTP_400_BAD_REQUEST)

            user = serializer.save()
            refresh = self.identity_service.login(
                email=serializer.validated_data["email"],
                password=serializer.validated_data["password"],
                request=request
            )[1]  # Get tokens from the tuple returned by login

            # Log signup activity
            log_activity(user, 'signup', _('User registered'), request)

            result = {
                "message": _("Registration successful."),
                "data": {
                    "user": UserSerializer(user).data,
                    "tokens": refresh,
                },
            }
            return Response(result, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error({"event": "SignUpView:post", "message": "Unexpected error occurred", "error": str(e)})
            raise e

class LoginView(ApiView):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.identity_service = IdentityService()

    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data)
            if not serializer.is_valid():
                result = {
                    "message": _("Invalid input. Please check the provided details."),
                    "errors": serializer.errors,
                }
                return Response(result, status=status.HTTP_400_BAD_REQUEST)

            user, tokens, error = self.identity_service.login(
                email=serializer.validated_data["email"],
                password=serializer.validated_data["password"],
                request=request
            )

            if not user:
                result = {
                    "message": error,
                }
                return Response(result, status=status.HTTP_400_BAD_REQUEST)

            # Log login activity
            log_activity(user, 'login', _('User logged in'), request)

            result = {
                "message": _("Login successful."),
                "data": {
                    "tokens": tokens,
                    "user": UserSerializer(user).data,
                },
            }
            return Response(result, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error({"event": "LoginView:post", "message": "Unexpected error occurred", "error": str(e)})
            raise e

class UserProfileView(ApiView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        try:
            user = request.user
            result = {
                "message": _("User profile retrieved successfully."),
                "data": {
                    "user": UserSerializer(user).data,
                },
            }
            return Response(result, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error({"event": "UserProfileView:get", "message": "Unexpected error occurred", "error": str(e)})
            raise e

class EmployerView(ApiView):
    permission_classes = [permissions.IsAuthenticated, IsOwner]
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    
    def get(self, request, pk=None):
        try:
            if pk:
                # Retrieve single employer
                employer = Employer.objects.get(pk=pk, user=request.user)
                result = {
                    "message": _("Employer retrieved successfully."),
                    "data": {
                        "employer": EmployerSerializer(employer).data,
                    },
                }
                return Response(result, status=status.HTTP_200_OK)
            else:
                # List all employers
                employers = Employer.objects.filter(user=request.user)
                result = {
                    "message": _("Employers retrieved successfully."),
                    "data": {
                        "employers": EmployerSerializer(employers, many=True).data,
                    },
                }
                return Response(result, status=status.HTTP_200_OK)
        except Employer.DoesNotExist:
            result = {
                "message": _("Employer not found."),
            }
            return Response(result, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error({"event": "EmployerViewSet:get", "message": "Unexpected error occurred", "error": str(e)})
            raise e
    
    def post(self, request):
        try:
            serializer = EmployerSerializer(data=request.data, context={'request': request})
            if not serializer.is_valid():
                result = {
                    "message": _("Invalid input. Please check the provided details."),
                    "errors": serializer.errors,
                }
                return Response(result, status=status.HTTP_400_BAD_REQUEST)
                
            employer = serializer.save()
            result = {
                "message": _("Employer created successfully."),
                "data": {
                    "employer": EmployerSerializer(employer).data,
                },
            }
            return Response(result, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error({"event": "EmployerViewSet:post", "message": "Unexpected error occurred", "error": str(e)})
            raise e
    
    def put(self, request, pk):
        try:
            employer = Employer.objects.get(pk=pk, user=request.user)
            serializer = EmployerSerializer(employer, data=request.data, context={'request': request})
            
            if not serializer.is_valid():
                result = {
                    "message": _("Invalid input. Please check the provided details."),
                    "errors": serializer.errors,
                }
                return Response(result, status=status.HTTP_400_BAD_REQUEST)
                
            employer = serializer.save()
            result = {
                "message": _("Employer updated successfully."),
                "data": {
                    "employer": EmployerSerializer(employer).data,
                },
            }
            return Response(result, status=status.HTTP_200_OK)
        except Employer.DoesNotExist:
            result = {
                "message": _("Employer not found."),
            }
            return Response(result, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error({"event": "EmployerViewSet:put", "message": "Unexpected error occurred", "error": str(e)})
            raise e
    
    def patch(self, request, pk):
        try:
            employer = Employer.objects.get(pk=pk, user=request.user)
            serializer = EmployerSerializer(employer, data=request.data, partial=True, context={'request': request})
            
            if not serializer.is_valid():
                result = {
                    "message": _("Invalid input. Please check the provided details."),
                    "errors": serializer.errors,
                }
                return Response(result, status=status.HTTP_400_BAD_REQUEST)
                
            employer = serializer.save()
            result = {
                "message": _("Employer updated successfully."),
                "data": {
                    "employer": EmployerSerializer(employer).data,
                },
            }
            return Response(result, status=status.HTTP_200_OK)
        except Employer.DoesNotExist:
            result = {
                "message": _("Employer not found."),
            }
            return Response(result, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error({"event": "EmployerViewSet:patch", "message": "Unexpected error occurred", "error": str(e)})
            raise e
    
    def delete(self, request, pk):
        try:
            employer = Employer.objects.get(pk=pk, user=request.user)
            employer.delete()
            result = {
                "message": _("Employer deleted successfully."),
            }
            return Response(result, status=status.HTTP_200_OK)
        except Employer.DoesNotExist:
            result = {
                "message": _("Employer not found."),
            }
            return Response(result, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error({"event": "EmployerViewSet:delete", "message": "Unexpected error occurred", "error": str(e)})
            raise e
